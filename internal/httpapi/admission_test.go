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
	"github.com/wyh-code26/attest/internal/policy"
)

// denyPolicy 是测试用的策略桩，永远返回拒绝。
type denyPolicy struct{}

func (p *denyPolicy) Evaluate(_ context.Context, _ *attest.Provenance) (bool, string) {
	return false, "test-policy-denied"
}

// buildAdmissionRequest 构造一个用于测试的 AdmissionReview JSON。
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

// setupTestHandler 构造测试用的 handler 和 fakeFetcher。
func setupTestHandler() (*httpapiHandler, *attest.FakeFetcher) {
	logger := discardLogger()

	// 预置一个合法的 digest
	validDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	fakeFetcher := attest.NewFakeFetcher(map[string]*attest.Provenance{
		validDigest: {
			BuildType: "https://slsa.dev/provenance/v1",
			Builder:   "https://github.com/actions/runner",
			SourceURI: "https://github.com/wyh-code26/attest",
		},
	})

	h := AdmissionHandler(AdmissionDeps{
		Logger:  logger,
		Fetcher: fakeFetcher,
		Policy:  &policy.AllowAll{},
	})

	return &httpapiHandler{h: h}, fakeFetcher
}

type httpapiHandler struct {
	h http.HandlerFunc
}

func TestAdmissionHandler_Allow(t *testing.T) {
	handler, _ := setupTestHandler()
	body := buildAdmissionRequest("t1", "nginx@sha256:1111111111111111111111111111111111111111111111111111111111111111")

	w := httptest.NewRecorder()
	handler.h.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Response == nil || !resp.Response.Allowed {
		t.Errorf("expected allowed=true, got %+v", resp.Response)
	}
}

func TestAdmissionHandler_Deny_InvalidImage(t *testing.T) {
	handler, _ := setupTestHandler()
	// 没有 @sha256
	body := buildAdmissionRequest("t2", "nginx:alpine")

	w := httptest.NewRecorder()
	handler.h.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	var resp AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Response.Allowed {
		t.Fatal("expected allowed=false")
	}
	if !strings.Contains(resp.Response.Result.Message, "must be pinned by sha256 digest") {
		t.Errorf("unexpected message: %s", resp.Response.Result.Message)
	}
}

func TestAdmissionHandler_Deny_MissingAttestation(t *testing.T) {
	handler, _ := setupTestHandler()
	// 带 sha256，但不在 FakeFetcher 的 map 里
	body := buildAdmissionRequest("t3", "nginx@sha256:2222222222222222222222222222222222222222222222222222222222222222")

	w := httptest.NewRecorder()
	handler.h.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	var resp AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Response.Allowed {
		t.Fatal("expected allowed=false")
	}
	if !strings.Contains(resp.Response.Result.Message, "no valid provenance") {
		t.Errorf("unexpected message: %s", resp.Response.Result.Message)
	}
}

func TestAdmissionHandler_Deny_PolicyDenied(t *testing.T) {
	// 使用拒绝策略
	logger := discardLogger()
	fakeFetcher := attest.NewFakeFetcher(map[string]*attest.Provenance{
		"sha256:1111111111111111111111111111111111111111111111111111111111111111": {
			BuildType: "https://slsa.dev/provenance/v1",
			Builder:   "https://github.com/actions/runner",
			SourceURI: "https://github.com/wyh-code26/attest",
		},
	})

	h := AdmissionHandler(AdmissionDeps{
		Logger:  logger,
		Fetcher: fakeFetcher,
		Policy:  &denyPolicy{},
	})

	body := buildAdmissionRequest("t4", "nginx@sha256:1111111111111111111111111111111111111111111111111111111111111111")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	var resp AdmissionReview
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Response.Allowed {
		t.Fatal("expected allowed=false")
	}
	if !strings.Contains(resp.Response.Result.Message, "denied: test-policy-denied") {
		t.Errorf("unexpected message: %s", resp.Response.Result.Message)
	}
}

func TestAdmissionHandler_InvalidJSON(t *testing.T) {
	handler, _ := setupTestHandler()
	w := httptest.NewRecorder()
	handler.h.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString("not json")))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAdmissionHandler_MissingRequest(t *testing.T) {
	handler, _ := setupTestHandler()
	w := httptest.NewRecorder()
	handler.h.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(`{"kind":"AdmissionReview"}`)))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}
