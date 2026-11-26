package verify

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type sigstoreVerifier struct {
	trust TrustMaterialProvider
	rules []IdentityRule
}

// NewSigstoreVerifier 构造一个使用 sigstore-go 的 Verifier。
// rules 不能为空——没有规则意味着拒绝所有，而不是接受所有。
func NewSigstoreVerifier(trust TrustMaterialProvider, rules []IdentityRule) (Verifier, error) {
	if trust == nil {
		return nil, errors.New("trust material provider must not be nil")
	}
	if len(rules) == 0 {
		return nil, errors.New("at least one identity rule is required")
	}
	return &sigstoreVerifier{trust: trust, rules: rules}, nil
}

func (v *sigstoreVerifier) Verify(ctx context.Context, bundleJSON []byte, expectedDigest string) (*VerifiedIdentity, error) {
	tm, err := v.trust.Get(ctx)
	if err != nil {
		// 拿不到信任根 = 无法验证 = 拒绝。不能降级为放行。
		return nil, fmt.Errorf("%w: get trusted material: %v", ErrSignatureInvalid, err)
	}

	verifier, err := verify.NewVerifier(tm,
		// 要求 SCT、透明度日志、观察者时间戳，满足 sigstore-go 的完整验证语义。
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: create verifier: %v", ErrSignatureInvalid, err)
	}

	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("%w: parse bundle: %v", ErrSignatureInvalid, err)
	}

	algorithm, digestBytes, err := parseDigest(expectedDigest)
	if err != nil {
		return nil, fmt.Errorf("parse digest: %w", err)
	}

	// 依次尝试每条身份规则。
	// 注意参数顺序：issuer, issuerRegex, sanValue, sanRegex。
	// 我们只传 issuer（精确）和 sanRegex（正则），所以中间两个空串。
	var lastErr error
	for _, rule := range v.rules {
		certID, err := verify.NewShortCertificateIdentity(rule.Issuer, "", "", rule.SANRegexp)
		if err != nil {
			lastErr = fmt.Errorf("invalid identity rule (issuer=%q, san=%q): %w", rule.Issuer, rule.SANRegexp, err)
			continue
		}

		_, err = verifier.Verify(&b, verify.NewPolicy(
			verify.WithArtifactDigest(algorithm, digestBytes),
			verify.WithCertificateIdentity(certID),
		))
		if err == nil {
			// 密码学验证通过。现在从**同一条已验证的证书链**里取出身份。
			// 注意：必须在验签成功后才提取，否则等于把未经背书的数据当事实。
			id, idErr := ExtractIdentityFromBundle(bundleJSON)
			if idErr != nil {
				// 验签过了但拿不到可认证身份 = 策略层没有判定依据 = 拒绝。
				// 这里直接返回错误而不降级读 payload（立项书 Non-negotiable 第 2 条）。
				return nil, idErr
			}
			return id, nil
		}
		lastErr = err
	}

	if lastErr == nil {
		return nil, fmt.Errorf("%w: no identity rule produced a result", ErrSignatureInvalid)
	}

	// 错误分类：把 sigstore-go 的错误映射成调用方可判断的类型。
	msg := lastErr.Error()
	switch {
	case strings.Contains(msg, "artifact digest"):
		return nil, fmt.Errorf("%w: %v", ErrDigestMismatch, lastErr)
	case strings.Contains(msg, "identity") || strings.Contains(msg, "certificate"):
		return nil, fmt.Errorf("%w: %v", ErrIdentityMismatch, lastErr)
	default:
		return nil, fmt.Errorf("%w: %v", ErrSignatureInvalid, lastErr)
	}
}

// parseDigest 把 "sha512:abcdef..." 拆成算法名和原始字节。
// 支持 sha256 和 sha512，其他算法直接报错——不要静默接受未知算法。
func parseDigest(s string) (algorithm string, raw []byte, err error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("digest must be in format <algorithm>:<hex>: %q", s)
	}
	algorithm = parts[0]
	switch algorithm {
	case "sha256", "sha512":
	default:
		return "", nil, fmt.Errorf("unsupported digest algorithm %q", algorithm)
	}
	raw, err = hex.DecodeString(parts[1])
	if err != nil {
		return "", nil, fmt.Errorf("decode hex digest: %w", err)
	}
	return algorithm, raw, nil
}
