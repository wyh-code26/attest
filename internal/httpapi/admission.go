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
	"github.com/wyh-code26/attest/internal/verify"
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

type AdmissionDeps struct {
	Logger  *slog.Logger
	Fetcher attest.Fetcher
	Policy  policy.Policy
	Metrics *metrics.Metrics
	Audit   *audit.Recorder
}

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
			writeJSON(w, d.Logger, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
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
			"uid", req.UID, "kind", req.Kind.Kind, "namespace", req.Namespace,
			"name", req.Name, "operation", req.Operation, "request_id", reqID,
		)

		baseEvent := audit.Event{
			Time: time.Now().UTC(), RequestID: reqID, UID: req.UID,
			Kind: req.Kind.Kind, Namespace: req.Namespace, Name: req.Name,
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
			d.Logger.Warn("extract container images failed", "reason", "missing_object",
				"err", err, "request_id", reqID, "uid", req.UID)
			writeJSON(w, d.Logger, http.StatusOK, denyReview(review.APIVersion, review.Kind, req.UID,
				"cannot extract image reference from object"))
			return
		}

		// 记住最后一条镜像的证据，供放行路径写审计。
		// 多镜像时审计只留一份摘要避免日志爆炸；每一条镜像的具体
		// 拒绝原因仍会各自单独记录（上面的每个 return 都会写一条）。
		var lastImage, lastDigest string
		var lastAtt *attest.Attestation

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
				d.Logger.Warn("invalid image reference", "reason", "invalid_image_ref",
					"image", image, "err", err, "request_id", reqID, "uid", req.UID)
				writeJSON(w, d.Logger, http.StatusOK, denyReview(review.APIVersion, review.Kind, req.UID,
					fmt.Sprintf("image %q must be pinned by sha256 digest", image)))
				return
			}

			att, err := d.Fetcher.Fetch(ctx, image)
			if err != nil {
				reason, logReason := classifyFetchError(err)
				d.Metrics.Record(reason)
				ev := baseEvent
				ev.Allowed = false
				ev.Reason = string(reason)
				ev.Image = image
				ev.Digest = digest
				ev.Message = "fetch provenance failed: " + err.Error()
				recordAudit(d.Logger, d.Audit, ev)
				d.Logger.Warn("fetch provenance failed", "reason", logReason,
					"image", image, "digest", digest, "err", err,
					"request_id", reqID, "uid", req.UID)
				writeJSON(w, d.Logger, http.StatusOK, denyReview(review.APIVersion, review.Kind, req.UID,
					fmt.Sprintf("no valid provenance for image %q: %v", image, err)))
				return
			}

			lastImage, lastDigest, lastAtt = image, digest, att

			// 策略只看已认证身份。att.Provenance 是 payload 自述值，
			// 仅进入审计日志，不参与任何判定（立项书 Non-negotiable 第 3 条）。
			allowed, policyReason := d.Policy.Evaluate(ctx, att.Identity)
			if !allowed {
				d.Metrics.Record(metrics.ResultDenyPolicy)
				ev := baseEvent
				ev.Allowed = false
				ev.Reason = string(metrics.ResultDenyPolicy)
				ev.Image = image
				ev.Digest = digest
				ev.PolicyReason = policyReason
				fillIdentityFields(&ev, att)
				ev.Message = "policy denied: " + policyReason
				recordAudit(d.Logger, d.Audit, ev)
				d.Logger.Warn("policy denied", "reason", "policy_denied",
					"policy_reason", policyReason, "image", image, "digest", digest,
					"source_repo", ev.SourceRepo, "build_signer", ev.BuildSigner,
					"runner_env", ev.RunnerEnv, "slsa_level", ev.SLSALevel,
					"declared_builder", ev.DeclaredBuilder,
					"request_id", reqID, "uid", req.UID)
				writeJSON(w, d.Logger, http.StatusOK, denyReview(review.APIVersion, review.Kind, req.UID,
					fmt.Sprintf("image %q denied: %s", image, policyReason)))
				return
			}
		}

		d.Metrics.Record(metrics.ResultAllow)
		ev := baseEvent
		ev.Allowed = true
		ev.Reason = string(metrics.ResultAllow)
		// 放行路径也要记录身份证据。
		// 否则一旦事后发生事故，只能查到"当时放行了"，无法回答
		// "是哪张证书、哪个源仓库、哪个 workflow 放进去的"。
		// 审计的价值一半在拒绝路径，另一半就在这里。
		if lastAtt != nil {
			fillIdentityFields(&ev, lastAtt)
			ev.Image = lastImage
			ev.Digest = lastDigest
		}
		recordAudit(d.Logger, d.Audit, ev)

		writeJSON(w, d.Logger, http.StatusOK, AdmissionReview{
			APIVersion: review.APIVersion, Kind: review.Kind,
			Response: &AdmissionResponse{UID: req.UID, Allowed: true},
		})
	}
}

// fillIdentityFields 把审计事件里“真值”与“自述值”分开填。
//
// 两边的字段刻意不同名：Builder/SLSALevel 来自签名证书，
// Declared* 来自 payload。混在一起会让事后审计无法判断
// “当时拦你是因为证书说你是 L2，还是因为你自己声称是 L2”。
func fillIdentityFields(ev *audit.Event, att *attest.Attestation) {
	if att.Identity != nil {
		ev.SLSALevel = att.Identity.SLSALevel()
		ev.SourceRepo = att.Identity.SourceRepoURI
		ev.BuildSigner = att.Identity.BuildSignerURI
		ev.RunnerEnv = att.Identity.RunnerEnv
	}
	if att.Provenance != nil {
		ev.DeclaredBuilder = att.Provenance.Builder
		ev.DeclaredBuildType = att.Provenance.BuildType
	}
}

// classifyFetchError 把 Fetch 的错误映射到指标和日志分类。
// 签名相关的错误必须归入 deny_invalid_signature，
// 因为它不是"没拉到"而是"拉到了但不可信"。
func classifyFetchError(err error) (metrics.Result, string) {
	switch {
	case errors.Is(err, attest.ErrAttestationNotFound):
		return metrics.ResultDenyMissingAttestation, "missing_attestation"
	case errors.Is(err, attest.ErrRegistryNotAllowed):
		// registry 不在白名单：这是配置/策略拒绝，不是"拉取失败"。
		// 单独归类，否则运维看 deny_fetch_error 会误以为是 registry 短暂不可用。
		return metrics.ResultDenyRegistryNotAllowed, "registry_not_allowed"
	case errors.Is(err, attest.ErrAttestationTooLarge):
		return metrics.ResultDenyAttestationTooLarge, "attestation_too_large"
	case errors.Is(err, verify.ErrSignatureInvalid):
		return metrics.ResultDenyInvalidSignature, "signature_invalid"
	case errors.Is(err, verify.ErrDigestMismatch):
		return metrics.ResultDenyInvalidSignature, "digest_mismatch"
	case errors.Is(err, verify.ErrIdentityMismatch):
		return metrics.ResultDenyInvalidSignature, "identity_mismatch"
	default:
		return metrics.ResultDenyFetchError, "fetch_error"
	}
}

func recordAudit(logger *slog.Logger, rec *audit.Recorder, ev audit.Event) {
	if err := rec.Record(ev); err != nil {
		logger.Error("audit record failed", "err", err, "request_id", ev.RequestID)
	}
}

func denyReview(apiVersion, kind, uid, message string) AdmissionReview {
	return AdmissionReview{
		APIVersion: apiVersion, Kind: kind,
		Response: &AdmissionResponse{
			UID: uid, Allowed: false,
			Result: &Status{Code: http.StatusForbidden, Message: message},
		},
	}
}

// podObjectView 是 Pod spec 的最小视图。
//
// 安全契约：凡是能跑容器镜像的字段都必须在此列全，漏一个就是绕过。
// 历史上只看了 containers，导致 initContainers 放任意未验证镜像直接过审。
// ephemeralContainers 由 UPDATE 操作（kubectl debug）带来，
// 虽然当前 webhook 只配了 CREATE，但一旦放开 operations 就是漏洞，所以一并覆盖。
type containerView struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

type podObjectView struct {
	Spec struct {
		InitContainers      []containerView `json:"initContainers"`
		Containers          []containerView `json:"containers"`
		EphemeralContainers []containerView `json:"ephemeralContainers"`
	} `json:"spec"`
}

// extractContainerImages 收集 Pod 内所有需要校验的容器镜像。
//
// 顺序为 initContainers → containers → ephemeralContainers，
// 保证同样的 Pod 产出稳定的错误信息（排障时不会随机变）。
// 只要有一个容器镜象为空就整体报错——空镜像不可能有合法 provenance，
// 放过它等于让一个 “什么都不写” 的字段绕过全部检查。
func extractContainerImages(req *AdmissionRequest) ([]string, error) {
	raw, err := req.GetObjectBytes()
	if err != nil {
		return nil, err
	}
	var pod podObjectView
	if err := json.Unmarshal(raw, &pod); err != nil {
		return nil, fmt.Errorf("unmarshal pod object: %w", err)
	}

	groups := []struct {
		label      string
		containers []containerView
	}{
		{"initContainers", pod.Spec.InitContainers},
		{"containers", pod.Spec.Containers},
		{"ephemeralContainers", pod.Spec.EphemeralContainers},
	}

	total := len(pod.Spec.InitContainers) + len(pod.Spec.Containers) + len(pod.Spec.EphemeralContainers)
	if total == 0 {
		return nil, errors.New("pod has no containers")
	}

	images := make([]string, 0, total)
	seen := make(map[string]struct{}, total)
	for _, g := range groups {
		for _, c := range g.containers {
			if c.Image == "" {
				if c.Name != "" {
					return nil, fmt.Errorf("image is empty for container %q in %s", c.Name, g.label)
				}
				return nil, fmt.Errorf("image is empty in %s", g.label)
			}
			// 同一个镜像在多个字段里重复出现时只验一次：
			// 验签是网络 + 密码学开销，去重避免侧载 Pod 把单次请求放大成 N 次校验。
			if _, ok := seen[c.Image]; ok {
				continue
			}
			seen[c.Image] = struct{}{}
			images = append(images, c.Image)
		}
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
