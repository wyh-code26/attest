package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

// AdmissionReview 是 kube-apiserver 发来的最小结构。
// 只定义本项目用到的字段，完整定义见 k8s.io/api/admission/v1。
// 手写而非引入 k8s SDK：项目叙事是"理解准入协议"，且阶段一只需极小子集。
type AdmissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

// AdmissionRequest 对应 AdmissionReview.request。
type AdmissionRequest struct {
	UID       string           `json:"uid"`
	Kind      GroupVersionKind `json:"kind"`
	Namespace string           `json:"namespace"`
	Name      string           `json:"name"`
	Operation string           `json:"operation"`
	Object    json.RawMessage  `json:"object,omitempty"`
	Raw       json.RawMessage  `json:"raw,omitempty"` // 部分工具用 base64 编码的原始字节
	DryRun    *bool            `json:"dryRun,omitempty"`
}

// GroupVersionKind 描述被准入对象的类型。
type GroupVersionKind struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

// AdmissionResponse 是回给 kube-apiserver 的结果。
// allowed 字段不能加 omitempty：false 必须显式出现在 JSON 里，
// 否则 apiserver 会按缺省值处理，语义不确定。
type AdmissionResponse struct {
	UID     string  `json:"uid"`
	Allowed bool    `json:"allowed"`
	Result  *Status `json:"status,omitempty"`
}

// Status 对应 metav1.Status 的子集。
type Status struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// GetObjectBytes 优先返回 request.Object，fallback 到 request.Raw（base64 解码）。
func (r *AdmissionRequest) GetObjectBytes() ([]byte, error) {
	if len(r.Object) > 0 {
		return r.Object, nil
	}
	if len(r.Raw) > 0 {
		decoded, err := base64.StdEncoding.DecodeString(string(r.Raw))
		if err != nil {
			return nil, fmt.Errorf("decode raw object: %w", err)
		}
		return decoded, nil
	}
	return nil, errors.New("neither object nor raw provided")
}

// AdmissionHandler 返回准入阶段的处理函数。
//
// 阶段一：协议解析 + allow-only。验证逻辑（Fetcher / Verifier / PolicyEngine）
// 在阶段二至三接入。签名刻意保持极简，等接口稳定后再抽 admission.New(...)。
//
// 契约（A6 落地）：
//   - ctx 直接取 r.Context()。deadline 由 Timeout 中间件统一挂，
//     handler 不得再嵌套 WithTimeout（见 Timeout 注释）。
//   - 所有阻塞 I/O 必须用带 ctx 的 API。阶段一没有外部 I/O，
//     阶段二引入 registry 拉取时这一点会被真正验证。
//   - 超时返回 deny 而非 504：AdmissionReview 的响应体必须是
//     allowed:false + status.message，HTTP 状态码仍是 200——
//     apiserver 靠 body 判断，不靠 HTTP 码。
//   - 日志区分 reason: timeout 与 reason: policy_denied（阶段三接入时）。
func AdmissionHandler(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, logger, http.StatusMethodNotAllowed, map[string]string{
				"error": "method not allowed",
			})
			return
		}

		ctx := r.Context()

		// 1 MiB 上限：准入请求体不应更大，超出直接拒绝。
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			logger.Error("read admission body", "err", err,
				"request_id", RequestIDFrom(ctx))
			writeJSON(w, logger, http.StatusBadRequest, map[string]string{
				"error": "read body",
			})
			return
		}

		var review AdmissionReview
		if err := json.Unmarshal(body, &review); err != nil {
			// 解析失败记录原始请求体前 512 字节，供接真实 apiserver 时排障。
			logger.Error("decode admission review", "err", err,
				"request_id", RequestIDFrom(ctx),
				"body_prefix", truncate(body, 512))
			writeJSON(w, logger, http.StatusBadRequest, map[string]string{
				"error": "invalid AdmissionReview",
			})
			return
		}

		if review.Request == nil {
			logger.Error("missing admission request",
				"request_id", RequestIDFrom(ctx),
				"body_prefix", truncate(body, 512))
			writeJSON(w, logger, http.StatusBadRequest, map[string]string{
				"error": "missing request",
			})
			return
		}

		logger.Info("admission review received",
			"uid", review.Request.UID,
			"kind", review.Request.Kind.Kind,
			"namespace", review.Request.Namespace,
			"name", review.Request.Name,
			"operation", review.Request.Operation,
			"request_id", RequestIDFrom(ctx),
		)

		// 阶段一：永远 allow。阶段二接 Fetcher/Verifier，阶段三接 PolicyEngine。
		writeJSON(w, logger, http.StatusOK, AdmissionReview{
			APIVersion: review.APIVersion,
			Kind:       review.Kind,
			Response: &AdmissionResponse{
				UID:     review.Request.UID,
				Allowed: true,
			},
		})
	}
}

// truncate 返回 b 的前 n 字节，用于日志记录脱敏的请求体前缀。
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
