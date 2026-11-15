package policy

import (
	"context"

	"github.com/wyh-code26/attest/internal/attest"
)

// Policy 判定一条 provenance 是否满足策略。
// 真实实现（阶段三）从声明式配置文件加载规则；测试实现由 AllowAll / DenyAll 等提供。
type Policy interface {
	Evaluate(ctx context.Context, prov *attest.Provenance) (allowed bool, reason string)
}
