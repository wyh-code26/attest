package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/wyh-code26/attest/internal/verify"
)

// 本文件的测试全部围绕一个核心契约：
// 策略只看 verify.VerifiedIdentity（来自签名证书），不看 attest.Provenance（payload）。

const (
	testBuildConfig = "https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1.2.3"
	testSignerURI   = "https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1.2.3"
	testSourceRepo  = "https://github.com/acme/app"
)

// l3Identity 返回一个满足 L3 判定规则的已认证身份。
func l3Identity() *verify.VerifiedIdentity {
	return &verify.VerifiedIdentity{
		Issuer:         "https://token.actions.githubusercontent.com",
		BuildSignerURI: testSignerURI,
		SourceRepoURI:  testSourceRepo,
		BuildConfigURI: testBuildConfig,
		RunnerEnv:      verify.RunnerEnvGitHubHosted,
	}
}

func TestSimplePolicy(t *testing.T) {
	tests := []struct {
		name           string
		rule           Rule
		id             *verify.VerifiedIdentity
		wantAllowed    bool
		wantReasonPart string
	}{
		{
			name:        "L3 identity with matching source repo and signer",
			rule:        Rule{MinSLSA: 3, AllowedSourceRepositories: []string{testSourceRepo}, AllowedBuildSignerRegex: []string{`^https://github\.com/acme/app/`}},
			id:          l3Identity(),
			wantAllowed: true,
		},
		{
			name:        "no restrictions configured allows L1",
			rule:        Rule{MinSLSA: 1},
			id:          &verify.VerifiedIdentity{Issuer: "https://example.com"},
			wantAllowed: true,
		},
		{
			name:           "self-hosted identity is L2, below L3 requirement",
			rule:           Rule{MinSLSA: 3},
			id:             &verify.VerifiedIdentity{RunnerEnv: verify.RunnerEnvSelfHosted, BuildConfigURI: testBuildConfig},
			wantAllowed:    false,
			wantReasonPart: "SLSA level 2 derived from certificate < required 3",
		},
		{
			name:           "github-hosted without build config is L2, passes L2 requirement",
			rule:           Rule{MinSLSA: 2},
			id:             &verify.VerifiedIdentity{RunnerEnv: verify.RunnerEnvGitHubHosted},
			wantAllowed:    true,
			wantReasonPart: "",
		},
		{
			name:           "github-hosted without build config fails L3 requirement",
			rule:           Rule{MinSLSA: 3},
			id:             &verify.VerifiedIdentity{RunnerEnv: verify.RunnerEnvGitHubHosted},
			wantAllowed:    false,
			wantReasonPart: "SLSA level 2 derived from certificate < required 3",
		},
		{
			name:           "empty identity is L1",
			rule:           Rule{MinSLSA: 2},
			id:             &verify.VerifiedIdentity{Issuer: "https://example.com"},
			wantAllowed:    false,
			wantReasonPart: "SLSA level 1",
		},
		{
			name:           "source repo not in allowlist",
			rule:           Rule{MinSLSA: 1, AllowedSourceRepositories: []string{testSourceRepo}},
			id:             &verify.VerifiedIdentity{SourceRepoURI: "https://github.com/evil/app"},
			wantAllowed:    false,
			wantReasonPart: "source repository",
		},
		{
			name:           "empty source repo with non-empty allowlist is denied",
			rule:           Rule{MinSLSA: 1, AllowedSourceRepositories: []string{testSourceRepo}},
			id:             &verify.VerifiedIdentity{BuildSignerURI: testSignerURI},
			wantAllowed:    false,
			wantReasonPart: "source repository",
		},
		{
			name:           "build signer does not match any pattern",
			rule:           Rule{MinSLSA: 1, AllowedBuildSignerRegex: []string{`^https://github\.com/acme/app/\.github/workflows/release\.yml@refs/tags/v`}},
			id:             &verify.VerifiedIdentity{BuildSignerURI: "https://github.com/evil/app/.github/workflows/release.yml@refs/tags/v1"},
			wantAllowed:    false,
			wantReasonPart: "build signer",
		},
		{
			name:           "empty build signer with non-empty pattern list is denied",
			rule:           Rule{MinSLSA: 1, AllowedBuildSignerRegex: []string{".*"}},
			id:             &verify.VerifiedIdentity{SourceRepoURI: testSourceRepo},
			wantAllowed:    false,
			wantReasonPart: "build signer",
		},
		{
			name:           "nil identity is denied",
			rule:           Rule{MinSLSA: 1},
			id:             nil,
			wantAllowed:    false,
			wantReasonPart: "nil",
		},
		{
			name:        "any of multiple signer patterns matches",
			rule:        Rule{MinSLSA: 1, AllowedBuildSignerRegex: []string{`^https://github\.com/other/`, `^https://github\.com/acme/`}},
			id:          &verify.VerifiedIdentity{BuildSignerURI: testSignerURI},
			wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewSimplePolicy(tt.rule)
			allowed, reason := p.Evaluate(context.Background(), tt.id)
			if allowed != tt.wantAllowed {
				t.Errorf("allowed = %v, want %v (reason: %s)", allowed, tt.wantAllowed, reason)
			}
			if tt.wantReasonPart != "" && !strings.Contains(reason, tt.wantReasonPart) {
				t.Errorf("reason = %q, want contains %q", reason, tt.wantReasonPart)
			}
		})
	}
}

// TestSimplePolicy_IgnoresPayload 是 H1 的核心回归测试。
//
// 场景：payload 自称 L3 + 合法 builder（旧实现会据此放行），
// 但证书 OID 显示是 self-hosted 的 L2 构建。
// 新实现必须拒绝——证明策略确实没有读 payload。
func TestSimplePolicy_IgnoresPayload(t *testing.T) {
	p := NewSimplePolicy(Rule{MinSLSA: 3})

	// 证书里是 self-hosted → L2。
	forgedIdentity := &verify.VerifiedIdentity{
		Issuer:         "https://token.actions.githubusercontent.com",
		BuildSignerURI: testSignerURI,
		SourceRepoURI:  testSourceRepo,
		BuildConfigURI: testBuildConfig,
		RunnerEnv:      verify.RunnerEnvSelfHosted,
	}

	allowed, reason := p.Evaluate(context.Background(), forgedIdentity)
	if allowed {
		t.Fatalf("self-hosted build must be denied when L3 is required; reason was empty")
	}
	if !strings.Contains(reason, "SLSA level 2") {
		t.Errorf("reason = %q, want it to cite SLSA level 2", reason)
	}
}

// TestSimplePolicy_L3PassesWhenPayloadClaimsLower 验证反向：
// 证书是 L3 就必须放行，哪怕 payload 自称 L1。
// 这样能防止有人"按 payload 最小值"实现而误拒合法镜像。
func TestSimplePolicy_L3PassesWhenPayloadClaimsLower(t *testing.T) {
	p := NewSimplePolicy(Rule{MinSLSA: 3})
	allowed, reason := p.Evaluate(context.Background(), l3Identity())
	if !allowed {
		t.Fatalf("L3 certificate must pass, got denied: %s", reason)
	}
}

// TestCompileRules 覆盖配置校验：非法配置必须拒绝启动。
func TestCompileRules(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
		field   string
	}{
		{"valid", Rule{MinSLSA: 3, AllowedSourceRepositories: []string{testSourceRepo}}, false, ""},
		{"valid no restrictions", Rule{MinSLSA: 1}, false, ""},
		{"min_slsa 0", Rule{MinSLSA: 0}, true, "min_slsa_level"},
		{"min_slsa 4", Rule{MinSLSA: 4}, true, "min_slsa_level"},
		{"min_slsa negative", Rule{MinSLSA: -1}, true, "min_slsa_level"},
		{"bad regex", Rule{MinSLSA: 1, AllowedBuildSignerRegex: []string{"("}}, true, "allowed_build_signer_regex"},
		{"empty regex entry", Rule{MinSLSA: 1, AllowedBuildSignerRegex: []string{""}}, true, "allowed_build_signer_regex"},
		{"empty repo entry", Rule{MinSLSA: 1, AllowedSourceRepositories: []string{""}}, true, "allowed_source_repositories"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CompileRules(tt.rule)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.field != "" {
				var re *RuleError
				if !asRuleError(err, &re) {
					t.Fatalf("expected *RuleError, got %T", err)
				}
				if re.Field != tt.field {
					t.Errorf("field = %q, want %q", re.Field, tt.field)
				}
			}
		})
	}
}

// TestSimplePolicy_SkipsInvalidRegexAtRuntime 验证运行时遇到坏正则不会崩溃、
// 也不会意外放宽。Loader 会在启动期拦截，这里只是兜底行为验证。
func TestSimplePolicy_SkipsInvalidRegexAtRuntime(t *testing.T) {
	// 全部正则都编译失败 → 不能当作"没配白名单"而放行。
	p := NewSimplePolicy(Rule{MinSLSA: 1, AllowedBuildSignerRegex: []string{"(", "["}})
	allowed, reason := p.Evaluate(context.Background(), &verify.VerifiedIdentity{BuildSignerURI: testSignerURI})
	if allowed {
		t.Fatal("all-invalid regex list must not silently allow")
	}
	if !strings.Contains(reason, "no pattern compiled") {
		t.Errorf("unexpected reason: %s", reason)
	}
}

// TestAllowAll 确认测试用实现行为。它只用于开发/测试，不参与生产。
func TestAllowAll(t *testing.T) {
	p := &AllowAll{}
	allowed, reason := p.Evaluate(context.Background(), nil)
	if !allowed || reason != "" {
		t.Errorf("AllowAll = (%v, %q), want (true, \"\")", allowed, reason)
	}
}

func asRuleError(err error, target **RuleError) bool {
	re, ok := err.(*RuleError)
	if ok {
		*target = re
	}
	return ok
}
