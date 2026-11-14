package httpapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestChain_Order(t *testing.T) {
	var order []string
	mw := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name+"_before")
				next.ServeHTTP(w, r)
				order = append(order, name+"_after")
			})
		}
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
	})

	Chain(h, mw("a"), mw("b")).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	want := []string{"a_before", "b_before", "handler", "b_after", "a_after"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, order[i], want[i])
		}
	}
}

func TestRequestID_ValidClientID(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-ID", "valid-id-123")
	w := httptest.NewRecorder()

	RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := RequestIDFrom(r.Context()); id != "valid-id-123" {
			t.Errorf("context ID = %q", id)
		}
	})).ServeHTTP(w, req)

	if got := w.Header().Get("X-Request-ID"); got != "valid-id-123" {
		t.Errorf("response header = %q", got)
	}
}

func TestRequestID_InvalidClientID(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-ID", "bad\nid")
	w := httptest.NewRecorder()

	RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := RequestIDFrom(r.Context())
		if id == "bad\nid" || id == "" {
			t.Errorf("should have regenerated, got %q", id)
		}
	})).ServeHTTP(w, req)
}

// TestChain_PanicRecordedAs500 锁死"Recover 在 Logging 内层"这个隐式契约。
func TestChain_PanicRecordedAs500(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}), RequestID(), Logging(logger), Recover(logger))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))

	if !strings.Contains(buf.String(), `"status":500`) {
		t.Fatalf("顺序契约破了：panic 后日志应为 500，实际:\n%s", buf.String())
	}
}

func TestRecover_PanicAfterWrite(t *testing.T) {
	logger := discardLogger()
	w := httptest.NewRecorder()

	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"partial":`))
		panic("after write")
	}), Logging(logger), Recover(logger))

	// 本用例只断言"不再写 500、body 未污染"。
	// 真正的"连接断开"语义需要 httptest.Server + 裸 TCP，属于阶段五。
	defer func() {
		if rec := recover(); rec != http.ErrAbortHandler {
			t.Fatalf("响应已写时应上抛 ErrAbortHandler，got %v", rec)
		}
		if w.Code != http.StatusOK {
			t.Errorf("状态码不应被改写，got %d", w.Code)
		}
		if strings.Contains(w.Body.String(), "internal server error") {
			t.Errorf("body 被污染: %q", w.Body.String())
		}
	}()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
}

func TestRecover_ErrAbortHandlerPassthrough(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	}), Logging(logger), Recover(logger))

	defer func() {
		if rec := recover(); rec != http.ErrAbortHandler {
			t.Fatalf("got %v", rec)
		}
		if strings.Contains(buf.String(), "panic recovered") {
			t.Errorf("ErrAbortHandler 不应记 error 日志")
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}

type countingWriter struct {
	http.ResponseWriter
	headerCalls int
}

func (c *countingWriter) WriteHeader(int) { c.headerCalls++ }

func TestStatusRecorder_DuplicateWriteHeader(t *testing.T) {
	cw := &countingWriter{ResponseWriter: httptest.NewRecorder()}
	sr := &statusRecorder{ResponseWriter: cw, status: http.StatusOK}

	sr.WriteHeader(http.StatusOK)
	sr.WriteHeader(http.StatusInternalServerError)

	if cw.headerCalls != 1 {
		t.Errorf("底层 WriteHeader 被调 %d 次，应为 1", cw.headerCalls)
	}
	if sr.status != http.StatusOK {
		t.Errorf("status = %d，第一次写入后不应被覆盖", sr.status)
	}
}

func TestTimeout_ExpiresAndHandlerCanStillWrite(t *testing.T) {
	// 20ms：足够短以加速测试，足够长以避开 CI 调度抖动。
	// <-ctx.Done() 保证确定性——不会提前返回，最坏情况只慢 20ms。
	w := httptest.NewRecorder()
	h := Timeout(20 * time.Millisecond)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		if !errors.Is(r.Context().Err(), context.DeadlineExceeded) {
			t.Errorf("ctx.Err() = %v, want DeadlineExceeded", r.Context().Err())
		}
		writeJSON(w, discardLogger(), http.StatusGatewayTimeout,
			map[string]string{"error": "handler timeout"})
	}))

	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", w.Code)
	}
}

func TestTimeout_FastHandlerUnaffected(t *testing.T) {
	w := httptest.NewRecorder()
	h := Timeout(time.Second)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Err() != nil {
			t.Errorf("未超时但 ctx 已取消: %v", r.Context().Err())
		}
		writeJSON(w, discardLogger(), http.StatusOK, map[string]string{"ok": "true"})
	}))

	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}
