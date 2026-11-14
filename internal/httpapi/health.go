package httpapi

import (
	"log/slog"
	"net/http"
	"sync/atomic"
)

// Readiness 管理就绪状态。用结构体而非包级变量：
// 测试每次 new 一个就是干净实例，互不污染；也支持 MarkNotReady 回退。
type Readiness struct {
	ready atomic.Bool
}

func (r *Readiness) MarkReady()    { r.ready.Store(true) }
func (r *Readiness) MarkNotReady() { r.ready.Store(false) }
func (r *Readiness) IsReady() bool { return r.ready.Load() }

// HealthzHandler 只反映进程存活，不检查外部依赖。
func HealthzHandler(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, logger, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// ReadyzHandler 未就绪时返回 503，并给出明确 reason。
func ReadyzHandler(logger *slog.Logger, readiness *Readiness) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if !readiness.IsReady() {
			writeJSON(w, logger, http.StatusServiceUnavailable, map[string]string{
				"status": "not_ready",
				"reason": "dependencies_not_initialized",
			})
			return
		}
		writeJSON(w, logger, http.StatusOK, map[string]string{"status": "ready"})
	}
}
