package policy

import (
	"context"
	"fmt"

	"github.com/wyh-code26/attest/internal/attest"
)

// Rule 是声明式的策略规则。
// 阶段三从 YAML 文件加载，阶段二曾硬编码在代码中。
// 字段的 yaml tag 决定了 YAML 配置文件里的键名。
type Rule struct {
	// MinSLSA 是要求的最低 SLSA 等级（1/2/3）。
	MinSLSA int `yaml:"min_slsa"`

	// AllowedBuilders 是允许的构建者列表，空表示不限制。
	// 对应 SLSA provenance 的 builder.id（如 GitHub Actions runner）。
	AllowedBuilders []string `yaml:"allowed_builders"`

	// AllowedTypes 是允许的 BuildType 列表，空表示不限制。
	// 对应 SLSA provenance 的 buildType（如 slsa.dev/provenance/v1）。
	AllowedTypes []string `yaml:"allowed_types"`
}

// SimplePolicy 根据 Rule 判定 provenance 是否满足策略。
// 它只接收解析好的 Provenance，不关心数据是来自 FakeFetcher 还是真实 OCI Registry。
// 这种解耦保证了策略判定可以完全脱离网络单测。
type SimplePolicy struct {
	rule Rule
}

func NewSimplePolicy(rule Rule) *SimplePolicy {
	return &SimplePolicy{rule: rule}
}

// Evaluate 按顺序检查：SLSA 等级 -> 构建者白名单 -> 构建类型白名单。
// 任何一项不满足都立即返回 false 和具体的拒绝原因。
// 返回的 reason 会写进 AdmissionResponse.status.message，供运维排障。
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
