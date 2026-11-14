package httpapi

import (
	"log/slog"
	"net/http"
	"time"
)

// RouterDeps 是 Router 的显式依赖。
//
// 只放 router 真正需要的字段。不要在这里塞整个 config.Config——
// 那会让 router 拿到 APIKey、ShutdownTimeout 等它不该关心的东西，
// 且未来 Config 新增字段时 router 会自动"看见"，破坏最小依赖。
//
// 命名以消费者定：消费者是 Router，所以是 RouterDeps，不是 Deps。
// 将来加 /metrics 时建 MetricsDeps，不要往这里追加字段。
type RouterDeps struct {
	Logger           *slog.Logger
	Readiness        *Readiness
	AdmissionHandler http.Handler
	HandlerTimeout   time.Duration
}

// NewRouter 装配路由与中间件。
//
// 中间件顺序即契约，从外到内：
//
//		RequestID → Logging → Recover → Timeout → mux → handler
//
//	 1. RequestID 最外：Logging 才能拿到 request_id。
//	 2. Logging 在 Recover 外：panic 被捕获后仍记到 status=500。
//	 3. Recover 在 Timeout 外：w 必须是 statusRecorder，Written() 检测才成立；
//	    同时 Recover 写 500 时不受 deadline 约束（未来响应体变大也不会被中途截断）。
//	 4. Timeout 在 mux 外：所有路由统一有 deadline，包括 404/405。
//
// 顺序写反不会报错、测试可能仍绿，但 fail closed 保护会静默退化。
// TestNewRouter_PanicRecords500 锁住这一点。
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
	if d.HandlerTimeout <= 0 {
		panic("httpapi: RouterDeps.HandlerTimeout must be positive")
	}

	mux := http.NewServeMux()
	mux.Handle("POST /admission", d.AdmissionHandler)
	mux.Handle("GET /healthz", HealthzHandler(d.Logger))
	mux.Handle("GET /readyz", ReadyzHandler(d.Logger, d.Readiness))

	return Chain(mux,
		RequestID(),
		Logging(d.Logger),
		Recover(d.Logger),
		Timeout(d.HandlerTimeout),
	)
}
