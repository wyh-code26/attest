package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/wyh-code26/attest/internal/attest"
	"github.com/wyh-code26/attest/internal/policy"
)

// AdmissionReview 是 kube-apiserver 发来的最小结构。
// 只定义本项目用到的字段，完整定义见 k8s.io/api/admission/v1。
type AdmissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

type AdmissionRequest struct {
	UID       string           `json:"uid"`
	Kind      GroupVersionKind `json:"kind"`
	Namespace string           `json:"namespace"`
	Name      string           `json:"name"`
	Operation string           `json:"operation"`
	Object    json.RawMessage  `json:"object,omitempty"`
	Raw       json.RawMessage  `json:"raw,omitempty"`
	DryRun    *bool            `json:"dryRun,omitempty"`
}

type GroupVersionKind struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

// allowed 字段不能加 omitempty：false 必须显式出现在 JSON 里。
type AdmissionResponse struct {
	UID     string  `json:"uid"`
	Allowed bool    `json:"allowed"`
	Result  *Status `json:"status,omitempty"`
}

type Status struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// GetObjectBytes 优先返回 Object，fallback 到 Raw（base64 解码）。
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

// AdmissionDeps 是 AdmissionHandler 的显式依赖。
// 命名规则：消费者名 + Deps。不建全局 Deps 惯例。
type AdmissionDeps struct {
	Logger  *slog.Logger
	Fetcher attest.Fetcher
	Policy  policy.Policy
}

// AdmissionHandler 返回准入阶段的处理函数。
//
// 阶段二完成：从 Pod 对象提取所有容器的镜像 digest，逐个 fetch provenance
// 并调用 policy 判定。任何一步失败，立即 fail closed 返回 deny。
//
// 契约（立项书 7.3 + Non-negotiable）：
//   - ctx 直接取 r.Context()，deadline 由 Timeout 中间件统一挂，不嵌套 WithTimeout。
//   - 所有阻塞 I/O 必须用带 ctx 的 API（Fetcher 内部实现负责）。
//   - 业务 deny 返回 HTTP 200 + allowed:false（准入协议要求），
//     协议层错误（解析失败）返回 4xx，由 apiserver 按 failurePolicy 处理。
//   - 日志区分 reason：missing_attestation / fetch_error / policy_denied /
//     invalid_image_ref / missing_object。排障方向必须清晰。
func AdmissionHandler(d AdmissionDeps) http.HandlerFunc {
	if d.Logger == nil {
		panic("httpapi: AdmissionDeps.Logger must not be nil")
	}
	if d.Fetcher == nil {
		panic("httpapi: AdmissionDeps.Fetcher must not be nil")
	}
	if d.Policy == nil {
		panic("httpapi: AdmissionDeps.Policy must not be nil")
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, d.Logger, http.StatusMethodNotAllowed, map[string]string{
				"error": "method not allowed",
			})
			return
		}

		ctx := r.Context()

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			d.Logger.Error("read admission body", "err", err,
				"request_id", RequestIDFrom(ctx))
			writeJSON(w, d.Logger, http.StatusBadRequest, map[string]string{
				"error": "read body",
			})
			return
		}

		var review AdmissionReview
		if err := json.Unmarshal(body, &review); err != nil {
			d.Logger.Error("decode admission review", "err", err,
				"request_id", RequestIDFrom(ctx),
				"body_prefix", truncate(body, 512))
			writeJSON(w, d.Logger, http.StatusBadRequest, map[string]string{
				"error": "invalid AdmissionReview",
			})
			return
		}

		if review.Request == nil {
			d.Logger.Error("missing admission request",
				"request_id", RequestIDFrom(ctx),
				"body_prefix", truncate(body, 512))
			writeJSON(w, d.Logger, http.StatusBadRequest, map[string]string{
				"error": "missing request",
			})
			return
		}

		req := review.Request
		d.Logger.Info("admission review received",
			"uid", req.UID,
			"kind", req.Kind.Kind,
			"namespace", req.Namespace,
			"name", req.Name,
			"operation", req.Operation,
			"request_id", RequestIDFrom(ctx),
		)

		// 从对象体提取容器镜像，逐个 fetch + verify。
		// 任何一步失败 → deny，不遗漏任何一个容器（fail closed）。
		images, err := extractContainerImages(req)
		if err != nil {
			d.Logger.Warn("extract container images failed",
				"reason", "missing_object",
				"err", err,
				"request_id", RequestIDFrom(ctx),
				"uid", req.UID,
			)
			writeJSON(w, d.Logger, http.StatusOK, denyReview(review.APIVersion, review.Kind, req.UID,
				"cannot extract image reference from object"))
			return
		}

		for _, image := range images {
			digest, err := parseImageDigest(image)
			if err != nil {
				d.Logger.Warn("invalid image reference",
					"reason", "invalid_image_ref",
					"image", image,
					"err", err,
					"request_id", RequestIDFrom(ctx),
					"uid", req.UID,
				)
				writeJSON(w, d.Logger, http.StatusOK, denyReview(review.APIVersion, review.Kind, req.UID,
					fmt.Sprintf("image %q must be pinned by sha256 digest", image)))
				return
			}

			prov, err := d.Fetcher.Fetch(ctx, digest)
			if err != nil {
				reason := "fetch_error"
				if errors.Is(err, attest.ErrAttestationNotFound) {
					reason = "missing_attestation"
				}
				d.Logger.Warn("fetch provenance failed",
					"reason", reason,
					"image", image,
					"digest", digest,
					"err", err,
					"request_id", RequestIDFrom(ctx),
					"uid", req.UID,
				)
				writeJSON(w, d.Logger, http.StatusOK, denyReview(review.APIVersion, review.Kind, req.UID,
					fmt.Sprintf("no valid provenance for image %q: %v", image, err)))
				return
			}

			allowed, reason := d.Policy.Evaluate(ctx, prov)
			if !allowed {
				d.Logger.Warn("policy denied",
					"reason", "policy_denied",
					"policy_reason", reason,
					"image", image,
					"digest", digest,
					"builder", prov.Builder,
					"buildType", prov.BuildType,
					"sourceURI", prov.SourceURI,
					"request_id", RequestIDFrom(ctx),
					"uid", req.UID,
				)
				writeJSON(w, d.Logger, http.StatusOK, denyReview(review.APIVersion, review.Kind, req.UID,
					fmt.Sprintf("image %q denied: %s", image, reason)))
				return
			}
		}

		writeJSON(w, d.Logger, http.StatusOK, AdmissionReview{
			APIVersion: review.APIVersion,
			Kind:       review.Kind,
			Response: &AdmissionResponse{
				UID:     req.UID,
				Allowed: true,
			},
		})
	}
}

// denyReview 构造一个准入拒绝响应。
// 协议规定：业务拒绝用 HTTP 200 + allowed:false，message 进 status.message。
func denyReview(apiVersion, kind, uid, message string) AdmissionReview {
	return AdmissionReview{
		APIVersion: apiVersion,
		Kind:       kind,
		Response: &AdmissionResponse{
			UID:     uid,
			Allowed: false,
			Result: &Status{
				Code:    http.StatusForbidden,
				Message: message,
			},
		},
	}
}

// podObjectView 是 Pod 对象的最小视图，只关心容器镜像。
// 不引入 k8s.io/api，项目叙事是"理解准入协议"。
type podObjectView struct {
	Spec struct {
		Containers []struct {
			Image string `json:"image"`
		} `json:"containers"`
	} `json:"spec"`
}

// extractContainerImages 从 AdmissionRequest 中取出所有容器的 image 引用。
// 若对象体解析失败，或没有任何容器，返回错误（handler 应 deny）。
func extractContainerImages(req *AdmissionRequest) ([]string, error) {
	raw, err := req.GetObjectBytes()
	if err != nil {
		return nil, err
	}

	var pod podObjectView
	if err := json.Unmarshal(raw, &pod); err != nil {
		return nil, fmt.Errorf("unmarshal pod object: %w", err)
	}
	if len(pod.Spec.Containers) == 0 {
		return nil, errors.New("pod has no containers")
	}

	images := make([]string, 0, len(pod.Spec.Containers))
	for _, c := range pod.Spec.Containers {
		if c.Image == "" {
			return nil, errors.New("container image is empty")
		}
		images = append(images, c.Image)
	}
	return images, nil
}

// parseImageDigest 从镜像引用中提取 sha256 digest。
//
// 接受的格式：repo[:tag]@sha256:<64 hex>。
// 只用 tag（如 nginx:latest）的镜像直接报错——没有 digest 就无法
// 可靠地关联 attestation，必须 deny（fail closed）。
func parseImageDigest(image string) (string, error) {
	at := strings.LastIndex(image, "@")
	if at < 0 {
		return "", errors.New("image is not pinned by digest")
	}
	digest := image[at+1:]
	const prefix = "sha256:"
	if !strings.HasPrefix(digest, prefix) {
		return "", fmt.Errorf("unsupported digest format: %s", digest)
	}
	hexPart := digest[len(prefix):]
	if len(hexPart) != 64 {
		return "", fmt.Errorf("invalid sha256 digest length: %d", len(hexPart))
	}
	for _, ch := range hexPart {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return "", fmt.Errorf("invalid hex character in digest: %q", ch)
		}
	}
	return digest, nil
}

// truncate 返回 b 的前 n 字节，用于日志记录脱敏的请求体前缀。
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
