package httpapi

import (
	"log/slog"
	"net/http"
	"time"
)

type RouterDeps struct {
	Logger           *slog.Logger
	Readiness        *Readiness
	AdmissionHandler http.Handler
	MetricsHandler   http.Handler
	HandlerTimeout   time.Duration
}

// NewRouter 装配路由与中间件。
// 中间件顺序：RequestID → Logging → Recover → Timeout → mux → handler。
func NewRouter(d RouterDeps) http.Handler {
	if d.Logger == nil {
		panic("httpapi: RouterDeps.Logger must not be nil")
	}
	if d.Readiness == nil {
		panic("httpapi: RouterDeps.Readiness must not be nil")
	}
	if d.AdmissionHandler == nil {
		panic("httpapi: RouterDeps.AdmissionHandler must not be nil")
	}
	if d.MetricsHandler == nil {
		panic("httpapi: RouterDeps.MetricsHandler must not be nil")
	}
	if d.HandlerTimeout <= 0 {
		panic("httpapi: RouterDeps.HandlerTimeout must be positive")
	}

	mux := http.NewServeMux()
	mux.Handle("POST /admission", d.AdmissionHandler)
	mux.Handle("GET /healthz", HealthzHandler(d.Logger))
	mux.Handle("GET /readyz", ReadyzHandler(d.Logger, d.Readiness))
	mux.Handle("GET /metrics", d.MetricsHandler)

	return Chain(mux,
		RequestID(),
		Logging(d.Logger),
		Recover(d.Logger),
		Timeout(d.HandlerTimeout),
	)
}
