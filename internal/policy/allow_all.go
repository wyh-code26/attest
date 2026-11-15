package policy

import (
	"context"

	"github.com/wyh-code26/attest/internal/attest"
)

// AllowAll 永远放行。阶段二早期用它在链路里占位，
// 阶段三被真正的声明式策略替换。
type AllowAll struct{}

func (p *AllowAll) Evaluate(_ context.Context, _ *attest.Provenance) (bool, string) {
	return true, ""
}
