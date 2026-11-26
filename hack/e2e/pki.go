// Package main 是 e2e 测试的签发与推镜工具。
//
// 它做三件事：
//  1. 生成一套一次性的测试信任根（Fulcio 链 + CT log + Rekor log），
//     并写出与生产格式一致的 trusted_root.json；
//  2. 用该根签出 DSSE 信封（in-toto provenance），组装成 sigstore bundle；
//  3. 把这些 bundle 作为 OCI attestation 推到进程内 registry。
//
// 这里刻意不复用生产代码里的任何测试开关——生产二进制通过
// ATTEST_TRUSTED_ROOT 指向本工具生成的 trusted_root.json，
// 走的是与线上完全相同的验签代码路径。
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// fulcioIssuer 与 SAN 是写在叶子证书里的身份事实。
// 策略层与 identities.yaml 会据此判定“谁签的”。
const (
	fulcioIssuer = "https://token.actions.githubusercontent.com"
	testSAN      = "https://github.com/attest-e2e/attest/.github/workflows/release.yml@refs/heads/main"
)

// OID 常量。Fulcio 把构建元数据写进证书扩展，
// 生产代码按这些 OID 提取 VerifiedIdentity。
var (
	oidIssuerV1       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidIssuerV2       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
	oidBuildSignerURI = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9}
	oidRunnerEnv      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 11}
	oidSourceRepoURI  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}
	oidSourceRepoHash = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 13}
	oidBuildConfigURI = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 18}
)

// 构建元数据。为了能通过 policy.yaml 的 L3 断言，
// BuildConfigURI 必须非空，且 RunnerEnv 必须是 github-hosted。
const (
	buildConfigURI   = testSAN
	buildSignerURI   = testSAN
	sourceRepoURI    = "https://github.com/attest-e2e/attest"
	sourceRepoDigest = "dae8bd8eb433a4147b4655c00fe73e0f22bc0fb1"
	runnerEnv        = "github-hosted"
)

// pki 是一整套测试信任材料。
type pki struct {
	rootCert     *x509.Certificate
	rootKey      *ecdsa.PrivateKey
	intermediate *x509.Certificate
	interKey     *ecdsa.PrivateKey

	// CT log：签 SCT 用。
	ctLogKey *ecdsa.PrivateKey
	ctLogID  []byte

	// Rekor：签 tlog 条目用。
	rekorKey *ecdsa.PrivateKey
	rekorID  []byte

	// TSA：签 RFC3161 时间戳用（本套测试不要求，但 trusted root 需可解析）。
	tsaCert *x509.Certificate
	tsaKey  *ecdsa.PrivateKey
}

// newPKI 生成完整测试信任根。全部为一次性随机密钥。
func newPKI() (*pki, error) {
	p := &pki{}

	// 1. 根证书：自签，仅用于测试。
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "attest-e2e-root", Organization: []string{"attest e2e"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("create root cert: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, fmt.Errorf("parse root cert: %w", err)
	}
	p.rootCert, p.rootKey = rootCert, rootKey

	// 2. 中间 CA：模拟 Fulcio 的签发证书。
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate intermediate key: %w", err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "attest-e2e-fulcio-intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("create intermediate cert: %w", err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		return nil, fmt.Errorf("parse intermediate cert: %w", err)
	}
	p.intermediate, p.interKey = interCert, interKey

	// 3. CT log 密钥。SCT 用它的私钥签，trusted_root.json 里存公钥。
	p.ctLogKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ctlog key: %w", err)
	}
	p.ctLogID = logID(p.ctLogKey.Public())

	// 4. Rekor 透明日志密钥。
	p.rekorKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate rekor key: %w", err)
	}
	p.rekorID = logID(p.rekorKey.Public())

	// 5. TSA：trusted_root.json 的 timestampAuthorities 需要可解析。
	tsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate tsa key: %w", err)
	}
	tsaTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "attest-e2e-tsa"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	tsaDER, err := x509.CreateCertificate(rand.Reader, tsaTmpl, rootCert, &tsaKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("create tsa cert: %w", err)
	}
	tsaCert, err := x509.ParseCertificate(tsaDER)
	if err != nil {
		return nil, fmt.Errorf("parse tsa cert: %w", err)
	}
	p.tsaCert, p.tsaKey = tsaCert, tsaKey

	return p, nil
}

// logID 计算 sigstore 约定格式的日志 ID：
// SHA256(SubjectPublicKeyInfo DER) 的前 32 字节。
func logID(pub crypto.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(der)
	return h[:]
}

// extension 构造一个 DER 编码的扩展值（UTF8String）。
func extension(oid asn1.ObjectIdentifier, value string) pkix.Extension {
	der, err := asn1.MarshalWithParams(value, "utf8")
	if err != nil {
		panic(err)
	}
	return pkix.Extension{Id: oid, Critical: false, Value: der}
}

// signCSRToLeaf 用中间 CA 签出一个 Fulcio 风格的叶子证书，
// 并把构建元数据写进扩展。sctExt 为空表示不带 SCT（用于篡改用例）。
func (p *pki) issueLeaf(leafPub crypto.PublicKey, sctExt *pkix.Extension) (*x509.Certificate, error) {
	return p.issueLeafWithSerial(leafPub, big.NewInt(time.Now().UnixNano()), sctExt)
}

// issueLeafWithSerial 允许调用方指定序列号。
//
// 内嵌 SCT 需要“同一张证书签两次”（先占位、后填真签名），
// 两次的序列号必须一致，否则去 SCT 后的 TBS 会变，SCT 签名失效。
func (p *pki) issueLeafWithSerial(leafPub crypto.PublicKey, serial *big.Int, sctExt *pkix.Extension) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "attest-e2e-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// Fulcio 把 OIDC 身份放在 SAN 里。
		ExtraExtensions: []pkix.Extension{
			extension(oidIssuerV1, fulcioIssuer),
			extension(oidIssuerV2, fulcioIssuer),
			extension(oidBuildSignerURI, buildSignerURI),
			extension(oidRunnerEnv, runnerEnv),
			extension(oidSourceRepoURI, sourceRepoURI),
			extension(oidSourceRepoHash, sourceRepoDigest),
			extension(oidBuildConfigURI, buildConfigURI),
		},
	}
	// SAN 用 URI 形式，与 Fulcio 一致。
	sanExt, err := sanExtension()
	if err != nil {
		return nil, err
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, sanExt)
	if sctExt != nil {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, *sctExt)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.intermediate, leafPub, p.interKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert: %w", err)
	}
	return x509.ParseCertificate(der)
}

// sanExtension 构造 SAN 扩展（只含一个 URI）。URI 型 GeneralName 的
// context tag 是 6，整段是 SEQUENCE OF GeneralName。
func sanExtension() (pkix.Extension, error) {
	raw := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(testSAN)}
	der, err := asn1.Marshal([]asn1.RawValue{raw})
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
		Value: der,
	}, nil
}

// pemEncode 把证书或密钥编码成 PEM。
func pemEncode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// hexID 把日志 ID 转成 sigstore JSON 里使用的形式。
func hexID(id []byte) string { return hex.EncodeToString(id) }
