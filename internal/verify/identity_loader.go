package verify

import (
	"errors"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

type identityFile struct {
	Identities []identityEntry `yaml:"identities"`
}

type identityEntry struct {
	Issuer    string `yaml:"issuer"`
	SANRegexp string `yaml:"san_regexp"`
}

// LoadIdentitiesFromFile 从 YAML 加载身份 allowlist。
//
// 校验：
//   - 文件不能为空。
//   - 每条规则必须有 issuer 和 san_regexp。
//   - san_regexp 必须能被 regexp 编译。
//
// 失败时返回 error——调用方必须拒绝启动，不能用空 allowlist 继续跑。
func LoadIdentitiesFromFile(path string) ([]IdentityRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identities file %s: %w", path, err)
	}
	var f identityFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse identities yaml %s: %w", path, err)
	}
	if len(f.Identities) == 0 {
		return nil, errors.New("identities file contains no rules")
	}
	rules := make([]IdentityRule, 0, len(f.Identities))
	for i, e := range f.Identities {
		if e.Issuer == "" {
			return nil, fmt.Errorf("identity #%d: issuer is required", i)
		}
		if e.SANRegexp == "" {
			return nil, fmt.Errorf("identity #%d: san_regexp is required", i)
		}
		if _, err := regexp.Compile(e.SANRegexp); err != nil {
			return nil, fmt.Errorf("identity #%d: invalid san_regexp: %w", i, err)
		}
		rules = append(rules, IdentityRule{Issuer: e.Issuer, SANRegexp: e.SANRegexp})
	}
	return rules, nil
}
