package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthzHandler(t *testing.T) {
	w := httptest.NewRecorder()
	HealthzHandler(discardLogger()).ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestReadyzHandler_NotReady(t *testing.T) {
	w := httptest.NewRecorder()
	ReadyzHandler(discardLogger(), &Readiness{}).ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestReadyzHandler_Ready(t *testing.T) {
	r := &Readiness{}
	r.MarkReady()
	w := httptest.NewRecorder()
	ReadyzHandler(discardLogger(), r).ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestReadyzHandler_ToggleBack(t *testing.T) {
	r := &Readiness{}
	r.MarkReady()
	r.MarkNotReady()
	w := httptest.NewRecorder()
	ReadyzHandler(discardLogger(), r).ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 after MarkNotReady", w.Code)
	}
}
