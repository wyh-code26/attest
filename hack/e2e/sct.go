package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

// oidSCT 是内嵌 SCT 列表扩展的 OID。
var oidSCT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// issueLeafWithSCT 签发一张内嵌 SCT 的叶子证书。
//
// 内嵌 SCT 的标准做法分两步走：
//  1. 先签出完整证书（带一个占位的 SCT 扩展），
//  2. 去掉该扩展得到 precert 的 TBS，用 CT log 私钥对该 TBS 签名，
//  3. 把签名结果重新写成 SCT 扩展，替换占位值。
//
// 只有走完这三步，sigstore 的 VerifySignedCertificateTimestamp
// （内部调用 ctutil.VerifySCT(embedded=true)）才会通过。
func (p *pki) issueLeafWithSCT(leafPub crypto.PublicKey) (*x509.Certificate, error) {
	// 关键：两次签发必须使用完全相同的模板字段（尤其是序列号），
	// 否则去 SCT 后的 TBS 与签名时不一致，CT 验签必然失败。
	serial := big.NewInt(time.Now().UnixNano())

	// 第一步：带占位 SCT 扩展签发，得到“形状正确”的证书。
	placeholder := pkix.Extension{Id: oidSCT, Value: placeholderSCTListExt()}
	dummy, err := p.issueLeafWithSerial(leafPub, serial, &placeholder)
	if err != nil {
		return nil, err
	}

	// 第二步：构造 precert 叶子（自动去掉 SCT 扩展）。
	// CT 库使用自己的 x509 类型，需从 DER 重新解析。
	ts := uint64(time.Now().UnixMilli())
	ctLeaf, err := ctx509.ParseCertificate(dummy.Raw)
	if err != nil {
		return nil, fmt.Errorf("ct parse leaf: %w", err)
	}
	ctInter, err := ctx509.ParseCertificate(p.intermediate.Raw)
	if err != nil {
		return nil, fmt.Errorf("ct parse intermediate: %w", err)
	}
	mtl, err := ct.MerkleTreeLeafForEmbeddedSCT([]*ctx509.Certificate{ctLeaf, ctInter}, ts)
	if err != nil {
		return nil, fmt.Errorf("build merkle leaf: %w", err)
	}

	// 待签名数据 = SCT 签名输入。
	sigInput, err := ct.SerializeSCTSignatureInput(ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: ctSHA256(p.ctLogKey.Public())},
		Timestamp:  ts,
		Extensions: ct.CTExtensions{},
	}, ct.LogEntry{Leaf: *mtl})
	if err != nil {
		return nil, fmt.Errorf("serialize sct input: %w", err)
	}

	// 第三步：CT log 私钥签名。
	digest := sha256.Sum256(sigInput)
	rawSig, err := ecdsa.SignASN1(rand.Reader, p.ctLogKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign sct: %w", err)
	}

	// 第四步：把签名组装成 SCT 并写回证书（复用同一序列号）。
	sctDer, err := marshalEmbeddedSCT(ts, rawSig, ctSHA256(p.ctLogKey.Public()))
	if err != nil {
		return nil, err
	}
	sctExt := pkix.Extension{Id: oidSCT, Value: sctDer}
	return p.issueLeafWithSerial(leafPub, serial, &sctExt)
}

// ctSHA256 返回 32 字节的日志密钥哈希（SCT 的 logID 字段）。
func ctSHA256(pub crypto.PublicKey) [32]byte {
	return sha256.Sum256(mustMarshalPKIX(pub))
}

func mustMarshalPKIX(pub crypto.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return der
}

// placeholderSCTListExt 返回一个结构合法但内容无意义的 SCTList 扩展值。
// 它只用于第一步签发：CT 库要求该扩展可解析（SCTList 至少 1 项），
// 但内容随后会被真实 SCT 覆盖，因此不需要签名有效。
func placeholderSCTListExt() []byte {
	sct := &ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: [32]byte{}},
		Timestamp:  uint64(time.Now().UnixMilli()),
		Extensions: ct.CTExtensions{},
		Signature: ct.DigitallySigned{
			Algorithm: tls.SignatureAndHashAlgorithm{Hash: tls.SHA256, Signature: tls.ECDSA},
			Signature: []byte{0x30, 0x00},
		},
	}
	sctList, err := x509util.MarshalSCTsIntoSCTList([]*ct.SignedCertificateTimestamp{sct})
	if err != nil {
		panic(err)
	}
	encoded, err := tls.Marshal(*sctList)
	if err != nil {
		panic(err)
	}
	der, err := asn1.Marshal(encoded)
	if err != nil {
		panic(err)
	}
	return der
}

// marshalEmbeddedSCT 生成“内嵌到证书里”的 SCT 扩展值。
//
// 内嵌形式是 SCTList 的 DER OCTET STRING 包装（RFC 6962 §3.3）。
// 不手写编码：直接复用 CT 库的序列化，避免长度前缀写错。
func marshalEmbeddedSCT(ts uint64, sig []byte, logKeyID [32]byte) ([]byte, error) {
	sct := &ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: logKeyID},
		Timestamp:  ts,
		Extensions: ct.CTExtensions{},
		Signature: ct.DigitallySigned{
			Algorithm: tls.SignatureAndHashAlgorithm{
				Hash:      tls.SHA256,
				Signature: tls.ECDSA,
			},
			Signature: sig,
		},
	}

	sctList, err := x509util.MarshalSCTsIntoSCTList([]*ct.SignedCertificateTimestamp{sct})
	if err != nil {
		return nil, fmt.Errorf("marshal sct list: %w", err)
	}
	encoded, err := tls.Marshal(*sctList)
	if err != nil {
		return nil, fmt.Errorf("marshal sct list tls: %w", err)
	}
	return asn1.Marshal(encoded)
}

// sha256Bytes 返回 SHA256 摘要的字节切片。
func sha256Bytes(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
