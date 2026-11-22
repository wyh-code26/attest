package policy

import (
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Loader 负责从某个来源加载策略。
//
// 阶段三只实现 FileLoader。CRD/ConfigMap Loader 推迟到阶段五，
// 因为那需要 informer 和 RBAC 配合，属于部署层复杂度。
type Loader interface {
	Load(ctx context.Context) (Policy, error)
}

// FileLoader 从本地 YAML 文件加载策略。
// 默认路径是 "policy.yaml"，可通过 ATTEST_POLICY_PATH 环境变量覆盖。
type FileLoader struct {
	Path string
}

func NewFileLoader(path string) *FileLoader {
	return &FileLoader{Path: path}
}

// Load 读取并解析 YAML，返回 SimplePolicy。
//
// 契约（fail closed）：
//   - 文件不存在、YAML 格式错误、规则字段非法，全部返回 error。
//   - 调用方（main.go）必须把 error 视为启动失败，不能降级为 AllowAll。
//     策略加载失败时放行所有请求，等于安全系统完全失效。
func (l *FileLoader) Load(_ context.Context) (Policy, error) {
	data, err := os.ReadFile(l.Path)
	if err != nil {
		return nil, fmt.Errorf("read policy file %s: %w", l.Path, err)
	}

	var rule Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("parse policy yaml %s: %w", l.Path, err)
	}

	// 基础校验：MinSLSA 必须在 1-3 之间。
	// 0 或负数意味着"没有策略"，4 意味着"超出 SLSA 定义"——两者都是配置错误。
	if rule.MinSLSA < 1 || rule.MinSLSA > 3 {
		return nil, fmt.Errorf("invalid policy: min_slsa must be 1-3, got %d", rule.MinSLSA)
	}

	return NewSimplePolicy(rule), nil
}
