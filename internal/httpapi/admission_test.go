package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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

// denyPolicy 永远返回拒绝，用于测试 policy denied 路径。
type denyPolicy struct{}

func (p *denyPolicy) Evaluate(_ context.Context, _ *verify.VerifiedIdentity) (bool, string) {
	return false, "test-policy-denied"
}

// observingPolicy 记录策略实际收到的身份，用于验证准入层没有读 payload。
type observingPolicy struct {
	got *verify.VerifiedIdentity
}

func (p *observingPolicy) Evaluate(_ context.Context, id *verify.VerifiedIdentity) (bool, string) {
	p.got = id
	return true, ""
}

// errorFetcher 永远返回预设的错误，用于测试 Fetch 的各类失败路径。
type errorFetcher struct {
	err error
}

func (f *errorFetcher) Fetch(_ context.Context, _ string) (*attest.Attestation, error) {
	return nil, f.err
}

const (
	validDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	validImage  = "nginx@" + validDigest
)

func buildAdmissionRequest(uid, image string) string {
	req := AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: &AdmissionRequest{
			UID:       uid,
			Kind:      GroupVersionKind{Kind: "Pod"},
			Namespace: "default",
			Name:      "test-pod",
			Operation: "CREATE",
			Object:    json.RawMessage(`{"spec":{"containers":[{"image":"` + image + `"}]}}`),
		},
	}
	b, _ := json.Marshal(req)
	return string(b)
}

type testEnv struct {
	handler http.HandlerFunc
	metrics *metrics.Metrics
	audit   *bytes.Buffer
	logs    *bytes.Buffer
}

// validIdentity 返回一个合规的已认证身份（github-hosted + build config → L3）。
func validIdentity() *verify.VerifiedIdentity {
	return &verify.VerifiedIdentity{
		Issuer:           "https://token.actions.githubusercontent.com",
		BuildSignerURI:   "https://github.com/wyh-code26/attest/.github/workflows/release.yml@refs/tags/v1.0.0",
		SourceRepoURI:    "https://github.com/wyh-code26/attest",
		SourceRepoDigest: "dae8bd8eb433a4147b4655c00fe73e0f22bc0fb1",
		BuildConfigURI:   "https://github.com/wyh-code26/attest/.github/workflows/release.yml@refs/tags/v1.0.0",
		RunnerEnv:        verify.RunnerEnvGitHubHosted,
	}
}

func newTestEnv(pol policy.Policy, fakeMap map[string]*attest.Provenance) *testEnv {
	logger := discardLogger()
	fakeFetcher := attest.NewFakeFetcherWithIdentities(fakeMap, identityMap(fakeMap))
	m := metrics.New()
	auditBuf := &bytes.Buffer{}
	auditRec := audit.NewRecorder(auditBuf)

	h := AdmissionHandler(AdmissionDeps{
		Logger:  logger,
		Fetcher: fakeFetcher,
		Policy:  pol,
		Metrics: m,
		Audit:   auditRec,
	})
	return &testEnv{handler: h, metrics: m, audit: auditBuf}
}

// newTestEnvWithFetcher 允许注入任意 Fetcher，并把 slog 输出重定向到 buffer。
// 专门用于测试 Fetch 的错误分类——需要同时断言 metrics、审计日志和 slog 日志。
func newTestEnvWithFetcher(fetcher attest.Fetcher, pol policy.Policy) *testEnv {
	m := metrics.New()
	auditBuf := &bytes.Buffer{}
	logsBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logsBuf, nil))

	h := AdmissionHandler(AdmissionDeps{
		Logger:  logger,
		Fetcher: fetcher,
		Policy:  pol,
		Metrics: m,
		Audit:   audit.NewRecorder(auditBuf),
	})
	return &testEnv{handler: h, metrics: m, audit: auditBuf, logs: logsBuf}
}

// identityMap 为 fakeMap 里的每个镜像配一份合规身份，
// 让"放行"路径测试不会被身份缺失挡住。
func identityMap(data map[string]*attest.Provenance) map[string]*verify.VerifiedIdentity {
	out := make(map[string]*verify.VerifiedIdentity, len(data))
	for k := range data {
		out[k] = validIdentity()
	}
	return out
}

func defaultFakeMap() map[string]*attest.Provenance {
	return map[string]*attest.Provenance{
		validImage: {
			BuildType: "https://slsa.dev/provenance/v1",
			Builder:   "https://github.com/actions/runner",
			SourceURI: "https://github.com/wyh-code26/attest",
		},
	}
}

func TestAdmissionHandler_Allow(t *testing.T) {
	env := newTestEnv(&policy.AllowAll{}, defaultFakeMap())
	body := buildAdmissionRequest("t1", validImage)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response == nil || !resp.Response.Allowed {
		t.Errorf("expected allow, got %+v", resp.Response)
	}
	if snap := env.metrics.Snapshot(); snap[metrics.ResultAllow] != 1 {
		t.Errorf("metrics allow = %d, want 1", snap[metrics.ResultAllow])
	}
	if !strings.Contains(env.audit.String(), `"allowed":true`) {
		t.Errorf("audit missing allow record:\n%s", env.audit.String())
	}
}

func TestAdmissionHandler_Deny_InvalidImage(t *testing.T) {
	env := newTestEnv(&policy.AllowAll{}, defaultFakeMap())
	body := buildAdmissionRequest("t2", "nginx:alpine")
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	var resp AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response.Allowed {
		t.Fatal("expected deny")
	}
	if !strings.Contains(resp.Response.Result.Message, "must be pinned by sha256 digest") {
		t.Errorf("unexpected message: %s", resp.Response.Result.Message)
	}
	if snap := env.metrics.Snapshot(); snap[metrics.ResultDenyInvalidImage] != 1 {
		t.Errorf("metrics deny_invalid_image = %d, want 1", snap[metrics.ResultDenyInvalidImage])
	}
	if !strings.Contains(env.audit.String(), `"reason":"deny_invalid_image"`) {
		t.Errorf("audit missing deny reason:\n%s", env.audit.String())
	}
}

func TestAdmissionHandler_Deny_MissingAttestation(t *testing.T) {
	env := newTestEnv(&policy.AllowAll{}, defaultFakeMap())
	body := buildAdmissionRequest("t3", "nginx@sha256:2222222222222222222222222222222222222222222222222222222222222222")
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	var resp AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response.Allowed {
		t.Fatal("expected deny")
	}
	if snap := env.metrics.Snapshot(); snap[metrics.ResultDenyMissingAttestation] != 1 {
		t.Errorf("metrics = %d, want 1", snap[metrics.ResultDenyMissingAttestation])
	}
}

func TestAdmissionHandler_Deny_PolicyDenied(t *testing.T) {
	env := newTestEnv(&denyPolicy{}, defaultFakeMap())
	body := buildAdmissionRequest("t4", validImage)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	var resp AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response.Allowed {
		t.Fatal("expected deny")
	}
	if !strings.Contains(resp.Response.Result.Message, "denied: test-policy-denied") {
		t.Errorf("unexpected message: %s", resp.Response.Result.Message)
	}
	if snap := env.metrics.Snapshot(); snap[metrics.ResultDenyPolicy] != 1 {
		t.Errorf("metrics = %d, want 1", snap[metrics.ResultDenyPolicy])
	}
	if !strings.Contains(env.audit.String(), `"policy_reason":"test-policy-denied"`) {
		t.Errorf("audit missing policy_reason:\n%s", env.audit.String())
	}
}

// ---- 签名错误的三条子路径 ----

func TestAdmissionHandler_Deny_SignatureInvalid(t *testing.T) {
	fetcher := &errorFetcher{err: fmt.Errorf("test: %w", verify.ErrSignatureInvalid)}
	env := newTestEnvWithFetcher(fetcher, &policy.AllowAll{})
	body := buildAdmissionRequest("t-sig", validImage)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	var resp AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response.Allowed {
		t.Fatal("expected deny")
	}
	if snap := env.metrics.Snapshot(); snap[metrics.ResultDenyInvalidSignature] != 1 {
		t.Errorf("metrics deny_invalid_signature = %d, want 1", snap[metrics.ResultDenyInvalidSignature])
	}
	if !strings.Contains(env.audit.String(), `"reason":"deny_invalid_signature"`) {
		t.Errorf("audit missing reason:\n%s", env.audit.String())
	}
	if !strings.Contains(env.logs.String(), `"reason":"signature_invalid"`) {
		t.Errorf("slog missing signature_invalid reason:\n%s", env.logs.String())
	}
}

func TestAdmissionHandler_Deny_DigestMismatch(t *testing.T) {
	fetcher := &errorFetcher{err: fmt.Errorf("test: %w", verify.ErrDigestMismatch)}
	env := newTestEnvWithFetcher(fetcher, &policy.AllowAll{})
	body := buildAdmissionRequest("t-dig", validImage)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	var resp AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response.Allowed {
		t.Fatal("expected deny")
	}
	if snap := env.metrics.Snapshot(); snap[metrics.ResultDenyInvalidSignature] != 1 {
		t.Errorf("metrics = %d, want 1", snap[metrics.ResultDenyInvalidSignature])
	}
	if !strings.Contains(env.audit.String(), `"reason":"deny_invalid_signature"`) {
		t.Errorf("audit missing reason:\n%s", env.audit.String())
	}
	if !strings.Contains(env.logs.String(), `"reason":"digest_mismatch"`) {
		t.Errorf("slog missing digest_mismatch reason:\n%s", env.logs.String())
	}
}

func TestAdmissionHandler_Deny_IdentityMismatch(t *testing.T) {
	fetcher := &errorFetcher{err: fmt.Errorf("test: %w", verify.ErrIdentityMismatch)}
	env := newTestEnvWithFetcher(fetcher, &policy.AllowAll{})
	body := buildAdmissionRequest("t-id", validImage)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	var resp AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response.Allowed {
		t.Fatal("expected deny")
	}
	if snap := env.metrics.Snapshot(); snap[metrics.ResultDenyInvalidSignature] != 1 {
		t.Errorf("metrics = %d, want 1", snap[metrics.ResultDenyInvalidSignature])
	}
	if !strings.Contains(env.audit.String(), `"reason":"deny_invalid_signature"`) {
		t.Errorf("audit missing reason:\n%s", env.audit.String())
	}
	if !strings.Contains(env.logs.String(), `"reason":"identity_mismatch"`) {
		t.Errorf("slog missing identity_mismatch reason:\n%s", env.logs.String())
	}
}

func TestAdmissionHandler_InvalidJSON(t *testing.T) {
	env := newTestEnv(&policy.AllowAll{}, defaultFakeMap())
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString("not json")))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if snap := env.metrics.Snapshot(); snap[metrics.ResultErrorBadRequest] != 1 {
		t.Errorf("metrics error_bad_request = %d, want 1", snap[metrics.ResultErrorBadRequest])
	}
}

func TestAdmissionHandler_MissingRequest(t *testing.T) {
	env := newTestEnv(&policy.AllowAll{}, defaultFakeMap())
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(`{"kind":"AdmissionReview"}`)))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAdmissionHandler_WrongMethod(t *testing.T) {
	env := newTestEnv(&policy.AllowAll{}, defaultFakeMap())
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, httptest.NewRequest("GET", "/admission", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
	if snap := env.metrics.Snapshot(); snap[metrics.ResultErrorMethodNotAllowed] != 1 {
		t.Errorf("metrics error_method_not_allowed = %d, want 1", snap[metrics.ResultErrorMethodNotAllowed])
	}
}

// ---- H2: initContainers / ephemeralContainers 不能被绕过 ----

const evilDigest = "sha256:9999999999999999999999999999999999999999999999999999999999999999"

func buildPodRequest(uid string, spec string) string {
	req := AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: &AdmissionRequest{
			UID:       uid,
			Kind:      GroupVersionKind{Kind: "Pod"},
			Namespace: "default",
			Name:      "test-pod",
			Operation: "CREATE",
			Object:    json.RawMessage(`{"spec":` + spec + `}`),
		},
	}
	b, _ := json.Marshal(req)
	return string(b)
}

// 主容器合法、initContainer 未验证——必须拒绝。
// 这是准入控制器最典型的绕过路径。
func TestAdmissionHandler_Deny_InitContainerUnverified(t *testing.T) {
	env := newTestEnv(&policy.AllowAll{}, defaultFakeMap())
	body := buildPodRequest("t-init",
		`{"initContainers":[{"name":"init","image":"evil@`+evilDigest+`"}],`+
			`"containers":[{"name":"main","image":"`+validImage+`"}]}`)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	var resp AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response.Allowed {
		t.Fatal("expected deny: initContainer image has no attestation")
	}
	if snap := env.metrics.Snapshot(); snap[metrics.ResultDenyMissingAttestation] != 1 {
		t.Errorf("metrics = %d, want 1", snap[metrics.ResultDenyMissingAttestation])
	}
}

// ephemeralContainers 同样必须被检查（kubectl debug 路径）。
func TestAdmissionHandler_Deny_EphemeralContainerUnverified(t *testing.T) {
	env := newTestEnv(&policy.AllowAll{}, defaultFakeMap())
	body := buildPodRequest("t-eph",
		`{"containers":[{"name":"main","image":"`+validImage+`"}],`+
			`"ephemeralContainers":[{"name":"dbg","image":"evil@`+evilDigest+`"}]}`)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	var resp AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response.Allowed {
		t.Fatal("expected deny: ephemeralContainer image has no attestation")
	}
}

// 三类容器全部合法时应放行——证明修复没有误伤。
func TestAdmissionHandler_Allow_AllContainerKinds(t *testing.T) {
	env := newTestEnv(&policy.AllowAll{}, defaultFakeMap())
	body := buildPodRequest("t-ok",
		`{"initContainers":[{"name":"init","image":"`+validImage+`"}],`+
			`"containers":[{"name":"main","image":"`+validImage+`"}],`+
			`"ephemeralContainers":[{"name":"dbg","image":"`+validImage+`"}]}`)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	var resp AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Response.Allowed {
		t.Fatalf("expected allow, got deny: %s", resp.Response.Result.Message)
	}
}

// initContainer 镜像为空字符串时不能当作"无镜像"放过。
func TestAdmissionHandler_Deny_EmptyInitImage(t *testing.T) {
	env := newTestEnv(&policy.AllowAll{}, defaultFakeMap())
	body := buildPodRequest("t-empty-init",
		`{"initContainers":[{"name":"init","image":""}],`+
			`"containers":[{"name":"main","image":"`+validImage+`"}]}`)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	var resp AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response.Allowed {
		t.Fatal("expected deny: empty initContainer image")
	}
	if !strings.Contains(env.audit.String(), "initContainers") {
		// 响应给客户端的消息刻意脱敏，可定位的原因落在审计与 slog 里。
		t.Errorf("audit should name the offending field, got %q", env.audit.String())
	}
}
