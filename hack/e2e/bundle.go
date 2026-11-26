package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protrekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// attestation 是一份可推送的 attestation 及其预期判定。
type attestation struct {
	// Name 用于日志与用例命名。
	Name string
	// BundleJSON 是序列化后的 sigstore bundle。
	BundleJSON []byte
}

// issueOptions 控制签发行为的差异，用于构造“合法”与“各种不合法”用例。
type issueOptions struct {
	// SubjectDigest 是 in-toto statement 里的 subject digest。
	// 应当等于目标镜像的 digest。
	SubjectDigest string
	// TamperPayload 为真时，在签名完成后篡改 payload 的一个字节，
	// 使 DSSE 签名与 payload 不再匹配。
	TamperPayload bool
}

// issueAttestation 用测试 PKI 签出一份 in-toto provenance bundle。
//
// 产出结构刻意与生产 bundle 同构：
//   - DSSE 信封（payloadType = application/vnd.in-toto+json）
//   - 叶子证书链（含内嵌 SCT）
//   - Rekor v1 tlog 条目（含 inclusion promise / SET）
//
// 生产代码的验签逻辑不需要任何改动即可处理它。
func (p *pki) issueAttestation(opts issueOptions) (*attestation, error) {
	// 1. in-toto statement（SLSA provenance v0.2）。
	statement := buildStatement(opts.SubjectDigest)
	payloadBytes, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("marshal statement: %w", err)
	}

	// 2. 生成一次性签名密钥与含 SCT 的叶子证书。
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	leaf, err := p.issueLeafWithSCT(&leafKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("issue leaf: %w", err)
	}

	// 3. DSSE 签名。PAE 是 DSSE 规范规定的预认证编码。
	payloadType := "application/vnd.in-toto+json"
	pae := dsse.PAE(payloadType, payloadBytes)
	digest := sha256.Sum256(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, leafKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign dsse: %w", err)
	}

	// 4. 可选：签名后篡改 payload，用于 A3 篡改用例。
	// 篡改发生在签名之后，因此签名不再覆盖新的 payload。
	finalPayload := payloadBytes
	if opts.TamperPayload {
		finalPayload = tamper(payloadBytes)
	}

	// 5. 构造 Rekor 条目（需要在最终 payload 上计算 hash）。
	rekorEntry, err := p.buildRekorEntry(payloadType, finalPayload, sig, leaf, leafKey)
	if err != nil {
		return nil, err
	}

	// 6. 组装 bundle。
	bundle := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.1+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_X509CertificateChain{
				X509CertificateChain: &protocommon.X509CertificateChain{
					Certificates: []*protocommon.X509Certificate{
						{RawBytes: leaf.Raw},
						{RawBytes: p.intermediate.Raw},
					},
				},
			},
			TlogEntries: []*protrekor.TransparencyLogEntry{rekorEntry},
		},
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				PayloadType: payloadType,
				Payload:     finalPayload,
				Signatures: []*protodsse.Signature{
					{
						Keyid: "",
						Sig:   sig,
					},
				},
			},
		},
	}

	out, err := protojson.MarshalOptions{Multiline: false}.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("marshal bundle: %w", err)
	}
	return &attestation{Name: opts.SubjectDigest, BundleJSON: out}, nil
}

// buildStatement 构造 SLSA provenance v0.2 的 in-toto statement。
func buildStatement(subjectDigest string) map[string]any {
	// subject 的 digest 形如 sha256:abc...
	algo, value, ok := splitDigest(subjectDigest)
	if !ok {
		algo, value = "sha256", subjectDigest
	}
	return map[string]any{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": []any{
			map[string]any{
				"name":   "attest-e2e/app",
				"digest": map[string]any{algo: value},
			},
		},
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": map[string]any{
			"builder": map[string]any{
				"id": buildSignerURI,
			},
			"buildType": buildConfigURI,
			"invocation": map[string]any{
				"configSource": map[string]any{
					"uri":    sourceRepoURI,
					"digest": map[string]any{"sha1": sourceRepoDigest},
				},
			},
		},
	}
}

// splitDigest 拆分 "sha256:abc" 形式的 digest。
func splitDigest(d string) (string, string, bool) {
	for i := 0; i < len(d); i++ {
		if d[i] == ':' {
			return d[:i], d[i+1:], true
		}
	}
	return "", "", false
}

// tamper 翻转 payload 中的一个字节，模拟中间人篡改。
// 选择改动 predicate 里的一个字符，保证 JSON 结构仍可解析，
// 从而让失败点停在“签名不匹配”而不是“解析失败”。
func tamper(payload []byte) []byte {
	out := make([]byte, len(payload))
	copy(out, payload)
	// 找到 "in-toto.io" 里的字符并翻转一个 bit。
	idx := indexOf(out, []byte("in-toto.io"))
	if idx < 0 {
		idx = len(out) / 2
	}
	out[idx] ^= 0x01
	return out
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// buildRekorEntry 构造一个 Rekor v1 透明日志条目，
// 并用测试 Rekor 密钥签出 SET（signed entry timestamp）。
func (p *pki) buildRekorEntry(payloadType string, payload, envSig []byte, leaf *x509.Certificate, leafKey crypto.Signer) (*protrekor.TransparencyLogEntry, error) {
	// envSig 必须是 bundle 里那份 DSSE 签名本身：sigstore-go 会逐字段
	// 比对 Rekor 条目签名与 bundle 签名，重新签一次会导致不匹配。
	// intoto v0.0.2 的 body：{apiVersion, kind, spec:{content:{envelope}}}。
	body := map[string]any{
		"apiVersion": "0.0.2",
		"kind":       "intoto",
		"spec": map[string]any{
			"content": map[string]any{
				// payloadHash 是 sigstore-go 取 DSSE payload 哈希的唯一来源，
				// 缺失会导致 "not a dsse_v001 or intoto_v002 entry"。
				"payloadHash": map[string]any{
					"algorithm": "sha256",
					"value":     fmt.Sprintf("%x", sha256.Sum256(payload)),
				},
				"envelope": map[string]any{
					"payloadType": payloadType,
					"payload":     "",
					"signatures": []any{
						map[string]any{
							"sig":       doubleB64(envSig),
							"publicKey": base64.StdEncoding.EncodeToString(pemEncode("CERTIFICATE", leaf.Raw)),
						},
					},
				},
			},
		},
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal rekor body: %w", err)
	}

	integratedTime := time.Now()
	logIndex := int64(1)
	logID := hex.EncodeToString(ctSHA256Bytes(p.rekorKey.Public()))

	// SET 签名覆盖：body / integratedTime / logIndex / logID。
	setPayload := map[string]any{
		"body":           base64.StdEncoding.EncodeToString(bodyJSON),
		"integratedTime": integratedTime.Unix(),
		"logIndex":       logIndex,
		"logID":          logID,
	}
	setJSON, err := json.Marshal(setPayload)
	if err != nil {
		return nil, fmt.Errorf("marshal set payload: %w", err)
	}
	canonical, err := jsoncanonicalizer.Transform(setJSON)
	if err != nil {
		return nil, fmt.Errorf("canonicalize set: %w", err)
	}
	setDigest := sha256.Sum256(canonical)
	setSig, err := ecdsa.SignASN1(rand.Reader, p.rekorKey, setDigest[:])
	if err != nil {
		return nil, fmt.Errorf("sign set: %w", err)
	}

	entry := &protrekor.TransparencyLogEntry{
		LogIndex:       logIndex,
		LogId:          &protocommon.LogId{KeyId: ctSHA256Bytes(p.rekorKey.Public())},
		KindVersion:    &protrekor.KindVersion{Kind: "intoto", Version: "0.0.2"},
		IntegratedTime: integratedTime.Unix(),
		// 这里不需要 inclusion proof：SET 作为集成承诺即可满足校验。
		InclusionPromise: &protrekor.InclusionPromise{
			SignedEntryTimestamp: setSig,
		},
		CanonicalizedBody: bodyJSON,
	}
	_ = leaf
	return entry, nil
}

// doubleB64 做两层 base64 编码。
//
// Rekor 的 intoto v0.0.2 body 里 payload/sig/publicKey 字段是 strfmt.Base64：
// swagger 反序列化时解一层，rekor 内部又把这些字节当 base64 字符串解一层，
// 因此写入时必须编码两次，否则报 "unable to base64 decode payload"。
func doubleB64(b []byte) string {
	return base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString(b)))
}

// ctSHA256Bytes 返回日志密钥的 SHA256 字节（sigstore 的 logID 约定）。
func ctSHA256Bytes(pub crypto.PublicKey) []byte {
	h := sha256.Sum256(mustMarshalPKIX(pub))
	return h[:]
}

var _ = timestamppb.Now
