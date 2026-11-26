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

	// fail closed：字段非法一律拒绝启动。
	// 尤其 allowed_build_signer_regex 里的正则如果编译失败，
	// 静默跳过会导致白名单意外变宽，必须在这里就拦住。
	if err := CompileRules(rule); err != nil {
		return nil, fmt.Errorf("parse policy yaml %s: %w", l.Path, err)
	}

	return NewSimplePolicy(rule), nil
}
