// Package verify 负责验证 Sigstore Bundle 的密码学签名与证书身份。
//
// 设计约束：
//   - sigstore-go 只出现在 sigstore_verifier.go，接口层不暴露它的类型。
//   - 信任根通过 TrustMaterialProvider 注入，支持热更新（Refresh）。
//   - 错误分类明确：签名、digest、身份三类分别可判断，供上层映射指标。
package verify

import (
	"context"
	"errors"
)

// Verifier 验证一个 Sigstore Bundle：
//   - Bundle 的签名有效；
//   - Bundle 绑定的 artifact digest 等于 expectedDigest；
//   - Bundle 的证书身份匹配某条 IdentityRule。
//
// expectedDigest 格式为 "sha256:<64 hex>"。
// 返回错误时，调用方应通过 errors.Is 判断具体的失败类型。
type Verifier interface {
	Verify(ctx context.Context, bundleJSON []byte, expectedDigest string) error
}

// IdentityRule 是允许的签名者身份。
//
// Issuer 精确匹配（如 "https://token.actions.githubusercontent.com"）。
// SANRegexp 是证书 SAN 的正则，用于匹配 GitHub Actions 的动态 workflow 路径。
// 两者必须同时匹配，缺一不可——只匹配 issuer 等于允许任何 GitHub Actions
// workflow 签名，这是安全漏洞。
type IdentityRule struct {
	Issuer    string
	SANRegexp string
}

// 错误分类。调用方用 errors.Is 判断，映射到不同的 metrics/audit reason。
var (
	// ErrSignatureInvalid 表示密码学验证失败：签名错误、证书链断裂、
	// 透明度日志缺失、时间戳无效等。
	ErrSignatureInvalid = errors.New("signature invalid")

	// ErrDigestMismatch 表示 Bundle 里的 subject digest 与当前镜像 digest 不一致。
	// 这是防止"用 A 镜像的证明冒充 B 镜像"的关键检查。
	ErrDigestMismatch = errors.New("attestation subject digest does not match image digest")

	// ErrIdentityMismatch 表示证书身份不在 allowlist 里。
	ErrIdentityMismatch = errors.New("certificate identity not allowed")
)
