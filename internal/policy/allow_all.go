package policy

import (
	"context"

	"github.com/wyh-code26/attest/internal/verify"
)

// AllowAll 永远放行。仅用于测试与链路占位，
// 生产路径必须使用 SimplePolicy——立项书 Non-negotiable 第 2 条不允许放行兜底。
type AllowAll struct{}

func (p *AllowAll) Evaluate(_ context.Context, _ *verify.VerifiedIdentity) (bool, string) {
	return true, ""
}
