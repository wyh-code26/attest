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

type testHandler struct {
	h http.HandlerFunc
}

func setupTestHandler() *testHandler {
	logger := discardLogger()
	fakeFetcher := attest.NewFakeFetcher(map[string]*attest.Provenance{
		validImage: {
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
	return &testHandler{h: h}
}

func TestAdmissionHandler_Allow(t *testing.T) {
	handler := setupTestHandler()
	body := buildAdmissionRequest("t1", validImage)

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
	handler := setupTestHandler()
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
	handler := setupTestHandler()
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
	logger := discardLogger()
	fakeFetcher := attest.NewFakeFetcher(map[string]*attest.Provenance{
		validImage: {
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

	body := buildAdmissionRequest("t4", validImage)
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
	handler := setupTestHandler()
	w := httptest.NewRecorder()
	handler.h.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString("not json")))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAdmissionHandler_MissingRequest(t *testing.T) {
	handler := setupTestHandler()
	w := httptest.NewRecorder()
	handler.h.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(`{"kind":"AdmissionReview"}`)))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}
