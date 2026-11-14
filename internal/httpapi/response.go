// Package httpapi 提供 HTTP 层：响应写入、探针、中间件、准入处理器。
//
// 本包禁止包级可变状态。所有依赖（logger、readiness、verifier 等）
// 必须通过参数或结构体显式传入。这是立项书 7.3 的硬约束。
package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// writeJSON 把 v 序列化为 JSON 写入响应。
//
// logger 必须非 nil（测试用 slog.New(slog.NewTextHandler(io.Discard, nil))）。
// 先 marshal 到内存再写 Header：序列化失败时可以返回 500，
// 而不是"200 + 半截 JSON"。在 failurePolicy: Fail 的准入场景下，
// 500 会触发显式拒绝部署，半截 JSON 只能靠 apiserver 容错兜底。
//
// v 为 nil 时只写状态码，不设 Content-Type、不写 body（符合 RFC 7231 对 204 的约束）。
func writeJSON(w http.ResponseWriter, logger *slog.Logger, status int, v any) {
	if v == nil {
		w.WriteHeader(status)
		return
	}

	buf, err := json.Marshal(v)
	if err != nil {
		logger.Error("marshal json response", "err", err, "status", status)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if _, err := w.Write(buf); err != nil {
		// Header 已发出，无法改状态码，只能记录。
		logger.Error("write json response body", "err", err, "status", status)
	}
}
