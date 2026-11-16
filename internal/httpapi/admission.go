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
	"time"

	"github.com/wyh-code26/attest/internal/attest"
	"github.com/wyh-code26/attest/internal/audit"
	"github.com/wyh-code26/attest/internal/metrics"
	"github.com/wyh-code26/attest/internal/policy"
)

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
	Metrics *metrics.Metrics
	Audit   *audit.Recorder
}

// AdmissionHandler 返回准入阶段的处理函数。
// 所有决策路径都通过 Metrics 计数、通过 Audit 落一条结构化日志。
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
	if d.Metrics == nil {
		panic("httpapi: AdmissionDeps.Metrics must not be nil")
	}
	if d.Audit == nil {
		panic("httpapi: AdmissionDeps.Audit must not be nil")
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			d.Metrics.Record(metrics.ResultErrorMethodNotAllowed)
			writeJSON(w, d.Logger, http.StatusMethodNotAllowed, map[string]string{
				"error": "method not allowed",
			})
			return
		}

		ctx := r.Context()
		reqID := RequestIDFrom(ctx)

		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			d.Metrics.Record(metrics.ResultErrorBadRequest)
			d.Logger.Error("read admission body", "err", err, "request_id", reqID)
			writeJSON(w, d.Logger, http.StatusBadRequest, map[string]string{"error": "read body"})
			return
		}

		var review AdmissionReview
		if err := json.Unmarshal(body, &review); err != nil {
			d.Metrics.Record(metrics.ResultErrorBadRequest)
			d.Logger.Error("decode admission review", "err", err,
				"request_id", reqID, "body_prefix", truncate(body, 512))
			writeJSON(w, d.Logger, http.StatusBadRequest, map[string]string{"error": "invalid AdmissionReview"})
			return
		}

		if review.Request == nil {
			d.Metrics.Record(metrics.ResultErrorBadRequest)
			d.Logger.Error("missing admission request",
				"request_id", reqID, "body_prefix", truncate(body, 512))
			writeJSON(w, d.Logger, http.StatusBadRequest, map[string]string{"error": "missing request"})
			return
		}

		req := review.Request
		d.Logger.Info("admission review received",
			"uid", req.UID,
			"kind", req.Kind.Kind,
			"namespace", req.Namespace,
			"name", req.Name,
			"operation", req.Operation,
			"request_id", reqID,
		)

		baseEvent := audit.Event{
			Time:      time.Now().UTC(),
			RequestID: reqID,
			UID:       req.UID,
			Kind:      req.Kind.Kind,
			Namespace: req.Namespace,
			Name:      req.Name,
			Operation: req.Operation,
		}

		images, err := extractContainerImages(req)
		if err != nil {
			d.Metrics.Record(metrics.ResultDenyNoObject)
			ev := baseEvent
			ev.Allowed = false
			ev.Reason = string(metrics.ResultDenyNoObject)
			ev.Message = "cannot extract image reference from object: " + err.Error()
			recordAudit(d.Logger, d.Audit, ev)
			d.Logger.Warn("extract container images failed",
				"reason", "missing_object", "err", err,
				"request_id", reqID, "uid", req.UID,
			)
			writeJSON(w, d.Logger, http.StatusOK, denyReview(review.APIVersion, review.Kind, req.UID,
				"cannot extract image reference from object"))
			return
		}

		for _, image := range images {
			digest, err := parseImageDigest(image)
			if err != nil {
				d.Metrics.Record(metrics.ResultDenyInvalidImage)
				ev := baseEvent
				ev.Allowed = false
				ev.Reason = string(metrics.ResultDenyInvalidImage)
				ev.Image = image
				ev.Message = "image must be pinned by sha256 digest: " + err.Error()
				recordAudit(d.Logger, d.Audit, ev)
				d.Logger.Warn("invalid image reference",
					"reason", "invalid_image_ref", "image", image, "err", err,
					"request_id", reqID, "uid", req.UID,
				)
				writeJSON(w, d.Logger, http.StatusOK, denyReview(review.APIVersion, review.Kind, req.UID,
					fmt.Sprintf("image %q must be pinned by sha256 digest", image)))
				return
			}

			prov, err := d.Fetcher.Fetch(ctx, image)
			if err != nil {
				reason := metrics.ResultDenyFetchError
				logReason := "fetch_error"
				if errors.Is(err, attest.ErrAttestationNotFound) {
					reason = metrics.ResultDenyMissingAttestation
					logReason = "missing_attestation"
				}
				d.Metrics.Record(reason)
				ev := baseEvent
				ev.Allowed = false
				ev.Reason = string(reason)
				ev.Image = image
				ev.Digest = digest
				ev.Message = "no valid provenance: " + err.Error()
				recordAudit(d.Logger, d.Audit, ev)
				d.Logger.Warn("fetch provenance failed",
					"reason", logReason, "image", image, "digest", digest, "err", err,
					"request_id", reqID, "uid", req.UID,
				)
				writeJSON(w, d.Logger, http.StatusOK, denyReview(review.APIVersion, review.Kind, req.UID,
					fmt.Sprintf("no valid provenance for image %q: %v", image, err)))
				return
			}

			allowed, policyReason := d.Policy.Evaluate(ctx, prov)
			if !allowed {
				d.Metrics.Record(metrics.ResultDenyPolicy)
				ev := baseEvent
				ev.Allowed = false
				ev.Reason = string(metrics.ResultDenyPolicy)
				ev.Image = image
				ev.Digest = digest
				ev.PolicyReason = policyReason
				ev.Builder = prov.Builder
				ev.SLSALevel = prov.SLSALevel
				ev.Message = "policy denied: " + policyReason
				recordAudit(d.Logger, d.Audit, ev)
				d.Logger.Warn("policy denied",
					"reason", "policy_denied", "policy_reason", policyReason,
					"image", image, "digest", digest,
					"builder", prov.Builder, "buildType", prov.BuildType, "sourceURI", prov.SourceURI,
					"request_id", reqID, "uid", req.UID,
				)
				writeJSON(w, d.Logger, http.StatusOK, denyReview(review.APIVersion, review.Kind, req.UID,
					fmt.Sprintf("image %q denied: %s", image, policyReason)))
				return
			}
		}

		d.Metrics.Record(metrics.ResultAllow)
		ev := baseEvent
		ev.Allowed = true
		ev.Reason = string(metrics.ResultAllow)
		recordAudit(d.Logger, d.Audit, ev)

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

func recordAudit(logger *slog.Logger, rec *audit.Recorder, ev audit.Event) {
	if err := rec.Record(ev); err != nil {
		logger.Error("audit record failed", "err", err, "request_id", ev.RequestID)
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
