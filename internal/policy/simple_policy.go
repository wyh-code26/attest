package policy

import (
	"context"
	"regexp"
	"strconv"

	"github.com/wyh-code26/attest/internal/verify"
)

// Policy 判定一次已验签的构建身份是否满足策略。
//
// 重要契约：入参必须是 verify.VerifiedIdentity，也就是从签名证书扩展里提取、
// 经密码学背书的字段。绝不接收 attest.Provenance——那份数据是推送方自填的，
// 用它做判定等于把策略建立在自述上（立项书 Non-negotiable 第 3 条）。
type Policy interface {
	Evaluate(ctx context.Context, id *verify.VerifiedIdentity) (allowed bool, reason string)
}

// Rule 是声明式的策略规则，字段名即 policy.yaml 的键名。
//
// 相比旧版（min_slsa / allowed_builders / allowed_types）的三点变化：
//   - allowed_builders   → allowed_build_signer_regex：按 workflow 引用正则匹配，
//     而不是匹配 builder 字符串常量；
//   - allowed_types      → allowed_source_repositories：判定被构建的源码仓库；
//   - 新增 min_slsa_level 语义保持不变，但等级改由证书字段推导。
type Rule struct {
	// MinSLSA 是要求的最低 SLSA 等级（1/2/3）。
	MinSLSA int `yaml:"min_slsa_level"`

	// AllowedSourceRepositories 是允许的源码仓库列表，空表示不限制。
	// 精确匹配证书里的 SourceRepoURI（如 "https://github.com/org/repo"）。
	AllowedSourceRepositories []string `yaml:"allowed_source_repositories"`

	// AllowedBuildSignerRegex 是允许的构建签名者正则列表，空表示不限制。
	// 匹配证书里的 BuildSignerURI，用正则是因为其中含分支/标签等可变部分。
	AllowedBuildSignerRegex []string `yaml:"allowed_build_signer_regex"`
}

// compiledRule 是 Rule 编译后的形式，正则只编译一次。
type compiledRule struct {
	minSLSA     int
	sourceRepos map[string]struct{}
	signerRes   []*regexp.Regexp
	signerSrc   []string
}

// SimplePolicy 根据 Rule 判定已认证的构建身份是否满足策略。
//
// 它不关心数据来自 FakeFetcher 还是真实 OCI Registry，也不触碰网络，
// 保证策略判定可以完全脱离 registry 单测。
type SimplePolicy struct {
	rule     Rule
	compiled compiledRule
}

// NewSimplePolicy 构造策略。正则在构造期编译，解析失败时返回 nil 规则列表，
// 由 Loader 负责拒绝启动——这里不返回 error 以保持签名简单，
// 但 CompileRules 提供了显式校验入口供 Loader 使用。
func NewSimplePolicy(rule Rule) *SimplePolicy {
	compiled := compiledRule{
		minSLSA:     rule.MinSLSA,
		sourceRepos: make(map[string]struct{}, len(rule.AllowedSourceRepositories)),
	}
	for _, r := range rule.AllowedSourceRepositories {
		if r != "" {
			compiled.sourceRepos[r] = struct{}{}
		}
	}
	for _, expr := range rule.AllowedBuildSignerRegex {
		re, err := regexp.Compile(expr)
		if err != nil {
			// 非法正则跳过。Loader 会通过 CompileRules 提前拦截并拒绝启动，
			// 所以正常路径下走不到这里。
			continue
		}
		compiled.signerRes = append(compiled.signerRes, re)
		compiled.signerSrc = append(compiled.signerSrc, expr)
	}
	return &SimplePolicy{rule: rule, compiled: compiled}
}

// CompileRules 校验策略规则，供 Loader 在启动期调用。
//
// fail closed：任何非法字段都返回 error，调用方必须拒绝启动。
func CompileRules(rule Rule) error {
	if rule.MinSLSA < 1 || rule.MinSLSA > 3 {
		return &RuleError{Field: "min_slsa_level", Msg: "must be 1-3"}
	}
	for i, expr := range rule.AllowedBuildSignerRegex {
		if expr == "" {
			return &RuleError{Field: "allowed_build_signer_regex", Msg: "entry must not be empty"}
		}
		if _, err := regexp.Compile(expr); err != nil {
			return &RuleError{
				Field: "allowed_build_signer_regex",
				Msg:   "entry " + strconv.Itoa(i) + " is not a valid regexp: " + err.Error(),
			}
		}
	}
	for i, repo := range rule.AllowedSourceRepositories {
		if repo == "" {
			return &RuleError{Field: "allowed_source_repositories", Msg: "entry " + strconv.Itoa(i) + " must not be empty"}
		}
	}
	return nil
}

// RuleError 描述单条策略字段的错误，便于运维定位到具体键名。
type RuleError struct {
	Field string
	Msg   string
}

func (e *RuleError) Error() string {
	return "invalid policy: " + e.Field + ": " + e.Msg
}

// Evaluate 按顺序检查：SLSA 等级 → 源码仓库白名单 → 构建签名者正则。
//
// 顺序是先便宜后昂贵，并保证错误信息指向最先失败的那一项——
// 排障时不需要反复试错。任何一项不满足都立即拒绝。
func (p *SimplePolicy) Evaluate(_ context.Context, id *verify.VerifiedIdentity) (bool, string) {
	if id == nil {
		return false, "verified identity is nil"
	}

	level := id.SLSALevel()
	if level < p.compiled.minSLSA {
		return false, "SLSA level " + strconv.Itoa(level) + " derived from certificate < required " + strconv.Itoa(p.compiled.minSLSA) +
			" (runner_env=" + quoteOrNone(id.RunnerEnv) + ", build_config_uri=" + quoteOrNone(id.BuildConfigURI) + ")"
	}

	if len(p.compiled.sourceRepos) > 0 {
		if _, ok := p.compiled.sourceRepos[id.SourceRepoURI]; !ok {
			return false, "source repository " + quoteOrNone(id.SourceRepoURI) + " not in allowlist"
		}
	}

	// 配置了正则但全部编译失败时，compiled.signerRes 为空。
	// 此时不能当作"没配白名单"而放行——那是 fail-open。
	// 用原始 rule 的条目数判断"是否有配置意图"。
	if len(p.rule.AllowedBuildSignerRegex) > 0 && len(p.compiled.signerRes) == 0 {
		return false, "allowed_build_signer_regex is configured but no pattern compiled successfully"
	}

	if len(p.compiled.signerRes) > 0 {
		// 先拦空值再跑正则。
		// 坑：`.*` 和 `^$` 都能匹配空串，所以“配了一条宽松正则”
		// 会让缺失 BuildSignerURI 的证书直接通过——这等于把
		// “证书没给信息”当成“匹配成功”，是典型的 fail-open。
		// 启用了签名者白名单就意味着必须有签名者，缺失就是拒绝。
		if id.BuildSignerURI == "" {
			return false, "build signer is absent from certificate, but allowed_build_signer_regex is configured"
		}
		matched := false
		for _, re := range p.compiled.signerRes {
			if re.MatchString(id.BuildSignerURI) {
				matched = true
				break
			}
		}
		if !matched {
			return false, "build signer " + quoteOrNone(id.BuildSignerURI) + " does not match any allowed pattern"
		}
	}

	return true, ""
}

func quoteOrNone(s string) string {
	if s == "" {
		return `"" (absent)`
	}
	return `"` + s + `"`
}
