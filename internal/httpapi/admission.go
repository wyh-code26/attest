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
type AdmissionDeps struct {
	Logger  *slog.Logger
	Fetcher attest.Fetcher
	Policy  policy.Policy
}

// AdmissionHandler 返回准入阶段的处理函数。
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
			// 验证镜像必须由 digest 固定，并提取 digest 用于日志。
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

			// 把完整 image 引用传给 Fetcher，以便它定位 registry 和 repository。
			prov, err := d.Fetcher.Fetch(ctx, image)
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

type podObjectView struct {
	Spec struct {
		Containers []struct {
			Image string `json:"image"`
		} `json:"containers"`
	} `json:"spec"`
}

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

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
