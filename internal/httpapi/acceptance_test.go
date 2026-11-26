package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wyh-code26/attest/internal/attest"
	"github.com/wyh-code26/attest/internal/audit"
	"github.com/wyh-code26/attest/internal/metrics"
	"github.com/wyh-code26/attest/internal/policy"
	"github.com/wyh-code26/attest/internal/verify"
)

// 本文件是 H1 修复的端到端验收：
// 策略判定必须基于证书里的身份（VerifiedIdentity），payload 里的自述值一律不采信。
//
// 对应立项书验收项：
//   A4 —— 达不到要求的构建者/等级被拒
//   A5 —— 构建者不在白名单被拒

// realPolicy 返回仓库里真实使用的那份策略规则（L3 + 本仓库源码 + release 签名者）。
func realPolicy() *policy.SimplePolicy {
	return policy.NewSimplePolicy(policy.Rule{
		MinSLSA: 3,
		AllowedSourceRepositories: []string{
			"https://github.com/wyh-code26/attest",
		},
		AllowedBuildSignerRegex: []string{
			`^https://github\.com/wyh-code26/attest/\.github/workflows/release\.ya?ml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$`,
		},
	})
}

// envWithIdentity 构造一个只对 validImage 返回指定身份的测试环境。
// payload 侧刻意填成"看起来完全合规"，用于验证策略不读它。
func envWithIdentity(t *testing.T, pol policy.Policy, id *verify.VerifiedIdentity) *testEnv {
	t.Helper()

	data := map[string]*attest.Provenance{
		validImage: {
			BuildType: "https://slsa.dev/provenance/v1",
			Builder:   "https://github.com/actions/runner",
			SourceURI: "https://github.com/wyh-code26/attest",
			SLSALevel: 3,
		},
	}
	identities := map[string]*verify.VerifiedIdentity{validImage: id}

	m := metrics.New()
	auditBuf := &bytes.Buffer{}
	h := AdmissionHandler(AdmissionDeps{
		Logger:  discardLogger(),
		Fetcher: attest.NewFakeFetcherWithIdentities(data, identities),
		Policy:  pol,
		Metrics: m,
		Audit:   audit.NewRecorder(auditBuf),
	})
	return &testEnv{handler: h, metrics: m, audit: auditBuf}
}

func runAdmission(t *testing.T, env *testEnv, uid string) (*AdmissionReview, int) {
	t.Helper()
	body := buildAdmissionRequest(uid, validImage)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	var resp AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v\nbody: %s", err, w.Body.String())
	}
	return &resp, w.Code
}

// TestAcceptance_A3_CompliantIdentityAllowed 验证合规身份被放行（A3）。
func TestAcceptance_A3_CompliantIdentityAllowed(t *testing.T) {
	env := envWithIdentity(t, realPolicy(), validIdentity())

	resp, code := runAdmission(t, env, "a3")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if resp.Response == nil || !resp.Response.Allowed {
		t.Fatalf("compliant L3 identity must be allowed, got %+v", resp.Response)
	}
	if snap := env.metrics.Snapshot(); snap[metrics.ResultAllow] != 1 {
		t.Errorf("metrics allow = %d, want 1", snap[metrics.ResultAllow])
	}
}

// TestAcceptance_A4_LevelTooLowDenied 验证 SLSA 等级不足被拒（A4）。
//
// 身份是 self-hosted → L2，而策略要求 L3。
func TestAcceptance_A4_LevelTooLowDenied(t *testing.T) {
	id := validIdentity()
	id.RunnerEnv = verify.RunnerEnvSelfHosted
	// 即便有完整的 build config，self-hosted 也封顶 L2。
	env := envWithIdentity(t, realPolicy(), id)

	resp, _ := runAdmission(t, env, "a4")
	if resp.Response.Allowed {
		t.Fatal("self-hosted (L2) must be denied when policy requires L3")
	}
	if !strings.Contains(resp.Response.Result.Message, "SLSA") {
		t.Errorf("deny message should cite SLSA level, got: %s", resp.Response.Result.Message)
	}
	if snap := env.metrics.Snapshot(); snap[metrics.ResultDenyPolicy] != 1 {
		t.Errorf("metrics deny_policy = %d, want 1", snap[metrics.ResultDenyPolicy])
	}
}

// TestAcceptance_A4_NoBuildConfigDenied 验证没有构建配置证据时被拒（A4）。
func TestAcceptance_A4_NoBuildConfigDenied(t *testing.T) {
	id := validIdentity()
	id.BuildConfigURI = "" // github-hosted 但无 build config → L2

	env := envWithIdentity(t, realPolicy(), id)
	resp, _ := runAdmission(t, env, "a4b")
	if resp.Response.Allowed {
		t.Fatal("identity without build config (L2) must be denied when L3 required")
	}
}

// TestAcceptance_A5_BuilderNotAllowlistedDenied 验证构建者不在白名单被拒（A5）。
//
// 三种变体：源仓库不符、签名 workflow 不符、源仓库字段缺失。
func TestAcceptance_A5_BuilderNotAllowlistedDenied(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*verify.VerifiedIdentity)
	}{
		{
			name: "source repository is a fork",
			mutate: func(id *verify.VerifiedIdentity) {
				id.SourceRepoURI = "https://github.com/attacker/attest"
			},
		},
		{
			name: "signer is a branch build not a release tag",
			mutate: func(id *verify.VerifiedIdentity) {
				id.BuildSignerURI = "https://github.com/wyh-code26/attest/.github/workflows/release.yml@refs/heads/main"
			},
		},
		{
			name: "signer is a different workflow",
			mutate: func(id *verify.VerifiedIdentity) {
				id.BuildSignerURI = "https://github.com/wyh-code26/attest/.github/workflows/test.yml@refs/tags/v1.0.0"
			},
		},
		{
			name: "source repository absent from certificate",
			mutate: func(id *verify.VerifiedIdentity) {
				id.SourceRepoURI = ""
			},
		},
		{
			name: "build signer absent from certificate",
			mutate: func(id *verify.VerifiedIdentity) {
				id.BuildSignerURI = ""
			},
		},
		{
			name: "unrelated builder entirely",
			mutate: func(id *verify.VerifiedIdentity) {
				id.BuildSignerURI = "https://gitlab.com/attacker/attest/-/jobs/1"
				id.SourceRepoURI = "https://gitlab.com/attacker/attest"
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id := validIdentity()
			c.mutate(id)

			env := envWithIdentity(t, realPolicy(), id)
			resp, _ := runAdmission(t, env, "a5")
			if resp.Response.Allowed {
				t.Fatalf("identity not in allowlist must be denied; identity was %+v", id)
			}
			if snap := env.metrics.Snapshot(); snap[metrics.ResultDenyPolicy] != 1 {
				t.Errorf("metrics deny_policy = %d, want 1", snap[metrics.ResultDenyPolicy])
			}
			// 审计里必须留下被拒的证书字段，方便事后追查。
			a := env.audit.String()
			if !strings.Contains(a, `"reason":"deny_policy"`) {
				t.Errorf("audit missing deny_policy:\n%s", a)
			}
		})
	}
}

// TestH1_ForgedPayloadIgnored 是 H1 的核心回归测试。
//
// 场景：攻击者推送一条 attestation，payload 里把 builder 写成
// "https://github.com/actions/runner"、SLSA 等级写成 3，看起来完美。
// 但它实际由 self-hosted 的运行器签名，证书里 RunnerEnv=self-hosted、源仓库是 fork。
//
// 旧实现读 payload → 放行（漏洞）。
// 新实现读证书 → 拒绝。
func TestH1_ForgedPayloadIgnored(t *testing.T) {
	// payload 侧故意填成完全合规（见 envWithIdentity 的 data）。
	// 证书侧是攻击者的真实身份。
	attackID := &verify.VerifiedIdentity{
		Issuer:         "https://token.actions.githubusercontent.com",
		BuildSignerURI: "https://github.com/attacker/attest/.github/workflows/release.yml@refs/heads/main",
		SourceRepoURI:  "https://github.com/attacker/attest",
		BuildConfigURI: "https://github.com/attacker/attest/.github/workflows/release.yml@refs/heads/main",
		RunnerEnv:      verify.RunnerEnvSelfHosted,
	}

	env := envWithIdentity(t, realPolicy(), attackID)
	resp, _ := runAdmission(t, env, "h1-forged")

	if resp.Response.Allowed {
		t.Fatal("H1 REGRESSION: attestation with forged payload was allowed. " +
			"Policy must judge by certificate identity, not payload content.")
	}
	if !strings.Contains(resp.Response.Result.Message, "denied") {
		t.Errorf("unexpected deny message: %s", resp.Response.Result.Message)
	}
}

// TestH1_PolicyReceivesCertificateIdentity 直接断言准入层交给策略的是证书身份，
// 而不是 payload 解析出的 Provenance。这是最贴近实现的一层证据。
func TestH1_PolicyReceivesCertificateIdentity(t *testing.T) {
	obs := &observingPolicy{}
	certID := validIdentity()
	certID.SourceRepoURI = "https://github.com/wyh-code26/attest"

	env := envWithIdentity(t, obs, certID)
	runAdmission(t, env, "h1-identity")

	if obs.got == nil {
		t.Fatal("policy received nil identity")
	}
	if obs.got != certID && obs.got.SourceRepoURI != certID.SourceRepoURI {
		t.Errorf("policy received %+v, want the certificate identity", obs.got)
	}
	// payload 里没有这些字段，只有证书有 —— 证明来源是证书。
	if obs.got.SourceRepoDigest != certID.SourceRepoDigest {
		t.Errorf("SourceRepoDigest = %q, want %q", obs.got.SourceRepoDigest, certID.SourceRepoDigest)
	}
	if obs.got.RunnerEnv != verify.RunnerEnvGitHubHosted {
		t.Errorf("RunnerEnv = %q, want github-hosted", obs.got.RunnerEnv)
	}
}

// TestH1_AuditSeparatesCertAndPayload 验证审计日志把证书事实与 payload 自述分开记录。
//
// 若两者混在同一字段名里，事后审计无法判断"这个 builder 是证书说的还是推送方说的"，
// 等于审计数据不可用。
func TestH1_AuditSeparatesCertAndPayload(t *testing.T) {
	env := envWithIdentity(t, realPolicy(), validIdentity())
	runAdmission(t, env, "h1-audit")

	a := env.audit.String()

	// 证书字段。
	if !strings.Contains(a, `"source_repo"`) {
		t.Errorf("audit missing certificate-derived source_repo:\n%s", a)
	}
	if !strings.Contains(a, `"build_signer"`) {
		t.Errorf("audit missing certificate-derived build_signer:\n%s", a)
	}
	if !strings.Contains(a, `"runner_env"`) {
		t.Errorf("audit missing certificate-derived runner_env:\n%s", a)
	}
	// payload 字段必须带 declared_ 前缀，与证书字段区分。
	if !strings.Contains(a, `"declared_builder"`) {
		t.Errorf("audit missing declared_builder (payload side):\n%s", a)
	}
	// 不能出现无前缀的 builder 字段——那会和证书字段混淆。
	if strings.Contains(a, `"builder":`) {
		t.Errorf("audit has un-prefixed builder field, ambiguous with certificate data:\n%s", a)
	}
}

// TestH1_NilIdentityDenied 验证身份缺失时拒绝，而不是放行。
//
// 这条路径对应"验签器未配置"或"证书无 Fulcio 扩展"：
// 此时 Identity 为 nil，任何真实策略都必须拒绝。
func TestH1_NilIdentityDenied(t *testing.T) {
	env := envWithIdentity(t, realPolicy(), nil)

	resp, _ := runAdmission(t, env, "h1-nil")
	if resp.Response.Allowed {
		t.Fatal("nil identity must be denied by policy")
	}
}
