package verify

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// 本文件实现"从签名证书里取出真实构建者身份"。
//
// 存在理由（对应立项书 Non-negotiable 第 3 条）：
// 证明文件（attestation payload）是推送方自己写的，其中的 builder / buildType /
// sourceURI 全是任意字符串，攻击者可以随便填。真正经过签名背书的只有证书本身，
// 所以策略判定必须只读证书扩展，绝不读 payload。
//
// 设计约束：
//   - 只从 Bundle 内携带的证书链本地解析，绝不发起任何网络请求
//     （立项书第 8 节：Sigstore 在线服务在国内可能不可达）。
//   - 扩展缺失时返回 ErrSignatureInvalid，不引入新的错误类型：
//     拿不到可认证的身份 = 无法验证 = 拒绝，与既有 fail-closed 契约一致。

// Fulcio 写入的证书扩展 OID。
//
// 历史上的编号演进在这里必须写清楚，否则很容易只支持其中一套：
//
//	2022–2023 年（sigstore 早期）：全部放在 arc 57264.1 下，
//	  1.1 issuer、1.9 build signer URI、1.11 runner env、1.12 source repo …
//	  本项目 testdata/bundle-provenance.json 里的真实证书属于这一代，
//	  它**没有** 57264.2 / 57264.4 / 57264.6 / 57264.8。
//
//	之后的版本把通用字段提升到独立 arc：
//	  57264.2 = build signer URI、57264.4 = source repo URI、
//	  57264.5 = source repo digest、57264.6 = build config URI、
//	  57264.8 = runner environment。
//
// 两套编号并存是现实，所以下面每个字段都同时声明新旧两个 OID，解析时优先新编号，
// 缺失则回退旧编号。只支持一套会导致另一代证书全部被误判为"缺 OID"而拒绝。
var (
	oidIssuer              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidIssuerV2            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
	oidBuildSignerURIOld   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9}
	oidSourceRepoURIOld    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}
	oidSourceRepoDigestOld = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 13}
	oidBuildConfigURIOld   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 18}
	oidRunnerEnvOld        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 11}

	oidBuildSignerURI   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}
	oidSourceRepoURI    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 4}
	oidSourceRepoDigest = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 5}
	oidBuildConfigURI   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 6}
	oidRunnerEnv        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 8}
)

// VerifiedIdentity 是从签名证书中提取、经签名背书的构建者身份。
//
// 这是策略层唯一允许读取的事实来源。字段全部来自 X.509 扩展，
// 不存在"调用方可以自己填"的入口——与 attest.Provenance 的根本区别。
type VerifiedIdentity struct {
	// Issuer 是签发 OIDC token 的机构，如
	// "https://token.actions.githubusercontent.com"。
	Issuer string

	// BuildSignerURI 是执行签名的 workflow 引用，如
	// "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1"。
	BuildSignerURI string

	// SourceRepoURI 是被构建的源码仓库，如 "https://github.com/org/repo"。
	SourceRepoURI string

	// SourceRepoDigest 是源码 commit SHA。
	SourceRepoDigest string

	// BuildConfigURI 是构建配置文件的引用。非空意味着构建过程由
	// 该配置声明式定义，是判定 SLSA L3 的必要条件之一。
	BuildConfigURI string

	// RunnerEnv 是执行构建的运行器环境，如 "github-hosted" / "self-hosted"。
	// github-hosted 代表构建平台由第三方强制控制，构建方无法篡改运行环境。
	RunnerEnv string
}

// SLSA 等级判定。
//
// 立项书 5.1 的 A4 要求"L2 证明 + 要求 L3 → deny"，但未定义等级判据。
// 这里的判据经项目负责人确认：
//
//	RunnerEnv == "github-hosted" 且 BuildConfigURI 非空        → L3
//	RunnerEnv == "self-hosted"                                 → L2
//	RunnerEnv 为空但 BuildConfigURI 非空                        → L2
//	其余                                                        → L1
//
// 依据 SLSA v1.0：L3 要求"构建过程由平台强制、构建方不可篡改"。
// github-hosted runner 满足这一点；self-hosted 的运行环境由构建方自控，
// 即使 build config 可读也不能证明未被篡改，因此封顶 L2。
const (
	SLSALevel1 = 1
	SLSALevel2 = 2
	SLSALevel3 = 3

	RunnerEnvGitHubHosted = "github-hosted"
	RunnerEnvSelfHosted   = "self-hosted"
)

// SLSALevel 按上述规则从已认证的证书字段推导 SLSA 等级。
//
// 注意：这里推导的是"证书能证明的等级"，不是 payload 自称的等级。
func (id *VerifiedIdentity) SLSALevel() int {
	if id == nil {
		return 0
	}
	hasBuildConfig := id.BuildConfigURI != ""

	switch id.RunnerEnv {
	case RunnerEnvGitHubHosted:
		if hasBuildConfig {
			return SLSALevel3
		}
		// runner 虽是平台托管，但没有构建配置声明，
		// 无法证明构建过程被声明式定义，降为 L2。
		return SLSALevel2
	case RunnerEnvSelfHosted:
		return SLSALevel2
	}

	if hasBuildConfig {
		return SLSALevel2
	}
	return SLSALevel1
}

// extractVerifiedIdentity 从 DER 编码的签名证书中提取已认证身份。
//
// 只解析第一张证书（叶子证书），因为它是真正执行签名的实体；
// 链上后续证书是 Fulcio 中间 CA 与根 CA，不携带工作负载身份。
func extractVerifiedIdentity(der []byte) (*VerifiedIdentity, error) {
	if len(der) == 0 {
		return nil, errors.New("certificate is empty")
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: parse signing certificate: %v", ErrSignatureInvalid, err)
	}

	extValues := make(map[string]string, len(cert.Extensions))
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidIssuer) && !isFulcioOID(ext.Id) {
			continue
		}
		s, err := decodeFulcioExtensionValue(ext.Value)
		if err != nil {
			// 单个扩展解码失败不阻断：其它扩展仍可能提供完整身份。
			// 关键字段缺失会在下面统一判定并拒绝。
			continue
		}
		extValues[ext.Id.String()] = s
	}

	pick := func(oids ...asn1.ObjectIdentifier) string {
		for _, oid := range oids {
			if v, ok := extValues[oid.String()]; ok && v != "" {
				return v
			}
		}
		return ""
	}

	id := &VerifiedIdentity{
		Issuer:           pick(oidIssuerV2, oidIssuer),
		BuildSignerURI:   pick(oidBuildSignerURI, oidBuildSignerURIOld),
		SourceRepoURI:    pick(oidSourceRepoURI, oidSourceRepoURIOld),
		SourceRepoDigest: pick(oidSourceRepoDigest, oidSourceRepoDigestOld),
		BuildConfigURI:   pick(oidBuildConfigURI, oidBuildConfigURIOld),
		RunnerEnv:        pick(oidRunnerEnv, oidRunnerEnvOld),
	}

	// 最小必要身份：issuer 用于匹配身份规则，BuildSignerURI 用于匹配
	// 构建者白名单。两者都拿不到时，策略层没有任何可判定的事实，
	// 必须在这里就拒绝，而不是让策略退化成"读 payload"。
	if id.Issuer == "" && id.BuildSignerURI == "" && id.SourceRepoURI == "" {
		return nil, fmt.Errorf("%w: signing certificate carries no Fulcio identity extensions",
			ErrSignatureInvalid)
	}

	return id, nil
}

func isFulcioOID(oid asn1.ObjectIdentifier) bool {
	prefix := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264}
	return len(oid) > len(prefix) && oid[:len(prefix)].Equal(prefix)
}

// decodeFulcioExtensionValue 解出扩展里的字符串值。
//
// Fulcio 各字段的内层编码在不同版本里不一致，三种都要能读：
//   - 原始字节：直接是文本内容（早期字段）；
//   - DER 包一层 UTF8String（tag 0x0c）；
//   - DER 包一层 PrintableString（tag 0x13）——纯 ASCII 内容用 asn1.Marshal
//     时会自动选这个 tag，实测真实证书与测试样例都会遇到。
//
// 只认 0x0c 会导致 ASCII 值带着 "\x13\x0d" 前缀漏出来，
// 进而让 RunnerEnv 永远匹配不上 "github-hosted"、SLSA 等级被错误降级。
func decodeFulcioExtensionValue(raw []byte) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("empty extension value")
	}

	// ASN.1 字符串类型的 tag：0x0c UTF8String、0x13 PrintableString、
	// 0x16 IA5String、0x14 TeletexString。
	switch raw[0] {
	case 0x0c, 0x13, 0x14, 0x16:
		var s string
		if rest, err := asn1.Unmarshal(raw, &s); err == nil && len(rest) == 0 {
			return s, nil
		}
		// asn1 解不开时按短格式手工切（长度 < 128）。
		if len(raw) >= 2 && raw[1] < 0x80 && int(raw[1]) == len(raw)-2 {
			return string(raw[2:]), nil
		}
	}

	// 原始字节形式：直接当 UTF-8 文本。
	return string(raw), nil
}

// ExtractIdentityFromBundle 从 Sigstore Bundle 的签名证书链中提取身份。
//
// 这是给测试和上层复用的入口。它只做本地解析，不触碰网络。
func ExtractIdentityFromBundle(bundleJSON []byte) (*VerifiedIdentity, error) {
	certs, err := certificateChainFromBundle(bundleJSON)
	if err != nil {
		return nil, err
	}
	return extractVerifiedIdentity(certs[0])
}

// certificateChainFromBundle 解开 Bundle JSON 里的 x509CertificateChain，
// 返回 DER 字节切片。
//
// 这里刻意手工解析而不是依赖 sigstore-go 的类型，原因：
// 失败时能给出精确的定位信息（是 JSON 结构不对，还是没带证书链），
// 而 sigstore-go 的 Unmarshal 只回一句通用错误。
func certificateChainFromBundle(bundleJSON []byte) ([][]byte, error) {
	var raw struct {
		VerificationMaterial struct {
			X509CertificateChain *struct {
				Certificates []struct {
					RawBytes string `json:"rawBytes"`
				} `json:"certificates"`
			} `json:"x509CertificateChain"`
		} `json:"verificationMaterial"`
	}

	if err := json.Unmarshal(bundleJSON, &raw); err != nil {
		return nil, fmt.Errorf("%w: parse bundle json: %v", ErrSignatureInvalid, err)
	}

	chain := raw.VerificationMaterial.X509CertificateChain
	if chain == nil || len(chain.Certificates) == 0 {
		return nil, fmt.Errorf("%w: bundle carries no x509 certificate chain", ErrSignatureInvalid)
	}

	certs := make([][]byte, 0, len(chain.Certificates))
	for i, c := range chain.Certificates {
		if c.RawBytes == "" {
			return nil, fmt.Errorf("%w: certificate #%d has empty rawBytes", ErrSignatureInvalid, i)
		}
		der, err := base64.StdEncoding.DecodeString(c.RawBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: decode certificate #%d: %v", ErrSignatureInvalid, i, err)
		}
		certs = append(certs, der)
	}
	return certs, nil
}
