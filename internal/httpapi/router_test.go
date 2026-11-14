package httpapi

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewRouter_Routes(t *testing.T) {
	logger := discardLogger()
	adm := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, logger, http.StatusOK, map[string]string{"allow": "true"})
	})
	ready := &Readiness{}

	tests := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{"admission", "POST", "/admission", http.StatusOK},
		{"healthz", "GET", "/healthz", http.StatusOK},
		{"readyz not ready", "GET", "/readyz", http.StatusServiceUnavailable},
		{"admission wrong method", "GET", "/admission", http.StatusMethodNotAllowed},
		{"unknown path", "GET", "/nope", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRouter(RouterDeps{
				Logger: logger, Readiness: ready,
				AdmissionHandler: adm, HandlerTimeout: time.Second,
			})
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path, nil))
			if w.Code != tt.want {
				t.Errorf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}

	ready.MarkReady()
	r := NewRouter(RouterDeps{Logger: logger, Readiness: ready, AdmissionHandler: adm, HandlerTimeout: time.Second})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != http.StatusOK {
		t.Errorf("ready status = %d, want 200", w.Code)
	}
}

func TestNewRouter_RejectsInvalidDeps(t *testing.T) {
	valid := func() RouterDeps {
		return RouterDeps{
			Logger: discardLogger(), Readiness: &Readiness{},
			AdmissionHandler: http.NotFoundHandler(), HandlerTimeout: time.Second,
		}
	}
	tests := []struct {
		name   string
		mutate func(*RouterDeps)
	}{
		{"nil logger", func(d *RouterDeps) { d.Logger = nil }},
		{"nil readiness", func(d *RouterDeps) { d.Readiness = nil }},
		{"nil admission handler", func(d *RouterDeps) { d.AdmissionHandler = nil }},
		{"zero timeout", func(d *RouterDeps) { d.HandlerTimeout = 0 }},
		{"negative timeout", func(d *RouterDeps) { d.HandlerTimeout = -time.Second }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := valid()
			tt.mutate(&d)
			defer func() {
				if recover() == nil {
					t.Fatal("expected panic")
				}
			}()
			NewRouter(d)
		})
	}
}

// TestNewRouter_PanicRecords500 锁死装配顺序。
// 若把 Recover 挪到 Logging 外层，w 不是 statusRecorder，
// Logging 也记不到 500，此测试必红。
func TestNewRouter_PanicRecords500(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	adm := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("boom") })

	r := NewRouter(RouterDeps{
		Logger: logger, Readiness: &Readiness{},
		AdmissionHandler: adm, HandlerTimeout: time.Second,
	})
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/admission", nil))

	out := buf.String()
	if !strings.Contains(out, `"status":500`) {
		t.Fatalf("panic 后日志应为 500，实际:\n%s", out)
	}
	if !strings.Contains(out, `"request_id"`) {
		t.Errorf("日志缺 request_id，说明 RequestID 不在最外层:\n%s", out)
	}
}
