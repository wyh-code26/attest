package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"runtime/debug"
	"time"
)

type Middleware func(http.Handler) http.Handler

// Chain 按书写顺序从外到内包裹：Chain(h, a, b) 的执行序是 a → b → h。
func Chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// ---- RequestID ----

type ctxKey string

const requestIDKey ctxKey = "request_id"

// 只接受白名单字符且长度受限的 ID，防止日志注入与超长 header。
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func RequestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Request-ID")
			if !requestIDPattern.MatchString(id) {
				id = generateRequestID()
			}
			w.Header().Set("X-Request-ID", id)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
		})
	}
}

func generateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// 极端降级：时间戳至少保证同一进程内不重复，避免所有请求共用一个 ID。
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// ---- Recover ----

// writtenReporter 由 statusRecorder 实现，用于判断响应是否已开始写。
type writtenReporter interface {
	Written() bool
}

// Recover 捕获 panic 并返回 500。
//
// 顺序契约：Recover 必须位于 Logging 内层，这样 w 是 statusRecorder，
// 才能通过 Written() 判断响应是否已写。
func Recover(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				// 标准库的 abort 语义必须原样上抛，不能吞。
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				logger.Error("panic recovered",
					"panic", rec,
					"stack", string(debug.Stack()),
					"request_id", RequestIDFrom(r.Context()),
				)

				// 响应已开始写时无法再改状态码。此时唯一正确动作是断开连接，
				// 让客户端看到"连接中断"而不是"200 + 非法 JSON"。
				if wr, ok := w.(writtenReporter); ok && wr.Written() {
					panic(http.ErrAbortHandler)
				}

				writeJSON(w, logger, http.StatusInternalServerError, map[string]string{
					"error": "internal server error",
				})
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// ---- Logging ----

type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.written {
		return // 幂等：避免 superfluous response.WriteHeader 日志
	}
	s.status = code
	s.written = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.written {
		s.written = true // 隐式 200，status 构造时已是 200
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Written() bool { return s.written }

// Unwrap 让 http.ResponseController 能穿透到原始 ResponseWriter
// （Flush、SetReadDeadline 等依赖它）。
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Logging 记录每个请求的结果。
// 用 defer 保证 panic 穿过时仍留下一条记录。
func Logging(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			defer func() {
				logger.Info("http request",
					"method", r.Method,
					"path", r.URL.Path,
					"status", rec.status,
					"duration_ms", time.Since(start).Milliseconds(),
					"request_id", RequestIDFrom(r.Context()),
					"remote", r.RemoteAddr,
				)
			}()

			next.ServeHTTP(rec, r)
		})
	}
}

// ---- Timeout ----

// Timeout 给请求上下文挂 deadline，仅此而已。
//
// 它不写响应、不检查超时——写响应永远是 handler 的责任。理由：
//  1. 中间件在 handler 返回后补写 504 会与已写响应冲突，
//     退化成 Recover 已经解决过的"半截 JSON"问题；
//  2. "超时拒绝"与"验证失败拒绝"必须在日志里可区分。
//
// 契约：
//   - cfg.HandlerTimeout 是唯一真源。handler 内直接 ctx := r.Context()，
//     不得再嵌套 WithTimeout——嵌套会让更早的 deadline 生效，配置静默失真。
//   - 所有阻塞 I/O 必须用带 ctx 的 API。
//   - 不得把 ctx 传给超出请求生命周期的 goroutine。
func Timeout(d time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
