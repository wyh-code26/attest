package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wyh-code26/attest/internal/attest"
	"github.com/wyh-code26/attest/internal/audit"
	"github.com/wyh-code26/attest/internal/metrics"
	"github.com/wyh-code26/attest/internal/policy"
)

type denyPolicy struct{}

func (p *denyPolicy) Evaluate(_ context.Context, _ *attest.Provenance) (bool, string) {
	return false, "test-policy-denied"
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
}

func newTestEnv(pol policy.Policy, fakeMap map[string]*attest.Provenance) *testEnv {
	logger := discardLogger()
	fakeFetcher := attest.NewFakeFetcher(fakeMap)
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
