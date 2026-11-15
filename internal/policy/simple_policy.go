package policy

import (
	"context"
	"fmt"

	"github.com/wyh-code26/attest/internal/attest"
)

// Rule 是声明式的策略规则。
// 阶段二从代码里构造，阶段三从 YAML 文件加载。
type Rule struct {
	// MinSLSA 是要求的最低 SLSA 等级（1/2/3）。
	MinSLSA int

	// AllowedBuilders 是允许的构建者列表，空表示不限制。
	// 对应 SLSA provenance 的 builder.id。
	AllowedBuilders []string

	// AllowedTypes 是允许的 BuildType 列表，空表示不限制。
	AllowedTypes []string
}

// SimplePolicy 根据 Rule 判定 provenance 是否满足策略。
type SimplePolicy struct {
	rule Rule
}

func NewSimplePolicy(rule Rule) *SimplePolicy {
	return &SimplePolicy{rule: rule}
}

func (p *SimplePolicy) Evaluate(_ context.Context, prov *attest.Provenance) (bool, string) {
	if prov == nil {
		return false, "provenance is nil"
	}

	if prov.SLSALevel < p.rule.MinSLSA {
		return false, fmt.Sprintf("SLSA level %d < required %d", prov.SLSALevel, p.rule.MinSLSA)
	}

	if len(p.rule.AllowedBuilders) > 0 {
		found := false
		for _, b := range p.rule.AllowedBuilders {
			if b == prov.Builder {
				found = true
				break
			}
		}
		if !found {
			return false, fmt.Sprintf("builder %q not in allowlist", prov.Builder)
		}
	}

	if len(p.rule.AllowedTypes) > 0 {
		found := false
		for _, t := range p.rule.AllowedTypes {
			if t == prov.BuildType {
				found = true
				break
			}
		}
		if !found {
			return false, fmt.Sprintf("build type %q not in allowlist", prov.BuildType)
		}
	}

	return true, ""
}
