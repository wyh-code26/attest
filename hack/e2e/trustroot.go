package e2e

import (
	"crypto/x509"
	"fmt"
	"time"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	trustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// trustRootMediaType 与生产 trusted_root.json 保持一致。
const trustRootMediaType = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

// trustedRootJSON 用官方 protobuf 类型构造一份 trusted_root.json。
//
// 手写 JSON 很容易在字段名、枚举值、时间格式上出错，
// 而 protojson 序列化能保证产出与线上文件同构，
// 从而让生产代码走完全相同的解析路径。
func (p *pki) trustedRootJSON() ([]byte, error) {
	// 有效期覆盖所有测试证书。
	validFor := &v1.TimeRange{
		Start: timestamppb.New(time.Now().Add(-2 * time.Hour)),
		End:   timestamppb.New(time.Now().Add(25 * time.Hour)),
	}

	// Fulcio：根 + 中间，最后一个为信任锚。
	fulcioChain := &v1.X509CertificateChain{
		Certificates: []*v1.X509Certificate{
			{RawBytes: p.intermediate.Raw},
			{RawBytes: p.rootCert.Raw},
		},
	}

	fulcioCA, err := p.certAuthority("https://fulcio.attest-e2e.invalid", fulcioChain, validFor)
	if err != nil {
		return nil, err
	}

	// TSA 链（单张自签）。
	tsaChain := &v1.X509CertificateChain{
		Certificates: []*v1.X509Certificate{{RawBytes: p.tsaCert.Raw}},
	}
	tsaCA, err := p.certAuthority("https://tsa.attest-e2e.invalid", tsaChain, validFor)
	if err != nil {
		return nil, err
	}

	// CT log：用公钥标识，SCT 校验时按 logID 查表。
	ctLog, err := p.transparencyLog("https://ctlog.attest-e2e.invalid", p.ctLogKey.Public(), validFor)
	if err != nil {
		return nil, err
	}

	// Rekor：tlog 条目校验用。
	rekorLog, err := p.transparencyLog("https://rekor.attest-e2e.invalid", p.rekorKey.Public(), validFor)
	if err != nil {
		return nil, err
	}

	root := &trustroot.TrustedRoot{
		MediaType:              trustRootMediaType,
		CertificateAuthorities: []*trustroot.CertificateAuthority{fulcioCA},
		TimestampAuthorities:   []*trustroot.CertificateAuthority{tsaCA},
		Ctlogs:                 []*trustroot.TransparencyLogInstance{ctLog},
		Tlogs:                  []*trustroot.TransparencyLogInstance{rekorLog},
	}

	out, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("marshal trusted root: %w", err)
	}
	return out, nil
}

// certAuthority 组装一个 CA 条目。
func (p *pki) certAuthority(uri string, chain *v1.X509CertificateChain, validFor *v1.TimeRange) (*trustroot.CertificateAuthority, error) {
	rootDER := chain.Certificates[len(chain.Certificates)-1].RawBytes
	cert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, fmt.Errorf("parse trust anchor: %w", err)
	}
	return &trustroot.CertificateAuthority{
		Subject: &v1.DistinguishedName{
			CommonName: cert.Subject.CommonName,
		},
		Uri:       uri,
		CertChain: chain,
		ValidFor:  validFor,
		Operator:  "attest-e2e.invalid",
	}, nil
}

// transparencyLog 组装一个日志条目。
func (p *pki) transparencyLog(baseURL string, pub any, validFor *v1.TimeRange) (*trustroot.TransparencyLogInstance, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal log pubkey: %w", err)
	}
	keyID := sha256Bytes(der)
	return &trustroot.TransparencyLogInstance{
		BaseUrl:       baseURL,
		HashAlgorithm: v1.HashAlgorithm_SHA2_256,
		PublicKey: &v1.PublicKey{
			RawBytes:   der,
			KeyDetails: v1.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			ValidFor:   validFor,
		},
		LogId: &v1.LogId{KeyId: keyID},
	}, nil
}
