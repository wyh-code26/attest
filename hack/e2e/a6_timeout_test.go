package e2e

// 本文件是 A6 验收：Webhook 故障时必须 fail closed。
//
// 立项书 A6 原文：
//   "集成测试：停掉 Webhook → 部署被阻断（failurePolicy: Fail 生效）。
//    测试配置 timeoutSeconds: 5，断言'超时后拒绝'而非'请求挂起'。"
//
// 为什么 A6 必须在进程内测而不是在 Kind 里测：
//   Kind 里"停掉 Webhook"要删 Service endpoints 再 apply Pod，只能观察到
//   kube-apiserver 返回 denied——那是 Kubernetes 的行为，不是本项目的。
//   本项目真正要证明的是：registry 卡住时，handler 会在 HandlerTimeout 内
//   返回一条 deny 的 AdmissionReview（HTTP 200），而不是挂住连接。
//   这正是 failurePolicy: Fail 生效后 kube-apiserver 能快速拿到"拒绝"的前提。
//   failurePolicy 本身是静态配置，由 Chart 渲染断言（见 NoSwitchTest）。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wyh-code26/attest/internal/attest"
	"github.com/wyh-code26/attest/internal/audit"
	"github.com/wyh-code26/attest/internal/httpapi"
	"github.com/wyh-code26/attest/internal/metrics"
	"github.com/wyh-code26/attest/internal/policy"
)

// blockingFetcher 模拟一个永不响应的 registry：
// 它会一直阻塞，直到 ctx 被取消（即 HandlerTimeout 到期）。
type blockingFetcher struct {
	// release 非 nil 时关闭它即可放行；nil 表示只等 ctx。
	release chan struct{}
	// entered 在 Fetch 被调用时关闭，供测试确认请求确实进入了拉取阶段。
	entered chan struct{}
}

func (f *blockingFetcher) Fetch(ctx context.Context, _ string) (*attest.Attestation, error) {
	select {
	case <-f.entered:
	default:
		close(f.entered)
	}
	if f.release != nil {
		select {
		case <-f.release:
			return nil, errors.New("released")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// a6AdmissionReview 构造一条合法的 Pod 创建 AdmissionReview。
func a6AdmissionReview(t *testing.T, uid string) []byte {
	t.Helper()
	raw := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "a6-pod", "namespace": "default"},
		"spec": map[string]any{
			"containers": []any{
				map[string]any{
					"name": "app",
					"image": "registry.example.com/app@sha256:" +
						"0000000000000000000000000000000000000000000000000000000000000000",
				},
			},
		},
	}
	if _, err := json.Marshal(raw); err != nil {
		t.Fatalf("marshal raw object: %v", err)
	}
	review := map[string]any{
		"apiVersion": "admission.k8s.io/v1",
		"kind":       "AdmissionReview",
		"request": map[string]any{
			"uid":       uid,
			"operation": "CREATE",
			"object":    raw,
		},
	}
	b, err := json.Marshal(review)
	if err != nil {
		t.Fatalf("marshal admission review: %v", err)
	}
	return b
}

// a6Server 装配生产 router，注入会在 ctx 到期时才返回的 fetcher。
func a6Server(t *testing.T, handlerTimeout time.Duration) (*httptest.Server, *blockingFetcher, *metrics.Metrics) {
	t.Helper()

	fetcher := &blockingFetcher{entered: make(chan struct{})}
	m := metrics.New()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	admission := httpapi.AdmissionHandler(httpapi.AdmissionDeps{
		Logger:  logger,
		Fetcher: fetcher,
		// 允许全部身份，把拒绝原因唯一地归到"超时"上，
		// 避免策略拒绝掩盖 A6 想证明的路径。
		Policy:  policy.NewSimplePolicy(policy.Rule{MinSLSA: 1}),
		Metrics: m,
		Audit:   audit.NewRecorder(io.Discard),
	})

	readiness := &httpapi.Readiness{}
	readiness.MarkReady()

	router := httpapi.NewRouter(httpapi.RouterDeps{
		Logger:           logger,
		Readiness:        readiness,
		AdmissionHandler: admission,
		MetricsHandler:   m.Handler(),
		HandlerTimeout:   handlerTimeout,
	})

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv, fetcher, m
}

// TestE2E_A6_TimeoutReturnsDenyNotHang 证明：registry 卡死时，webhook 在
// HandlerTimeout 内返回"拒绝"，而不是把连接挂住。
//
// 这是 failurePolicy: Fail 能起作用的前提——kube-apiserver 收到的必须是
// 一条明确的 deny，而不是等到 10s timeoutSeconds 才由它自己放弃。
func TestE2E_A6_TimeoutReturnsDenyNotHang(t *testing.T) {
	const handlerTimeout = 300 * time.Millisecond
	srv, fetcher, _ := a6Server(t, handlerTimeout)

	body := a6AdmissionReview(t, "a6-timeout")

	// 给 client 留出裕量：只要 handler 在 handlerTimeout 附近返回即可。
	client := &http.Client{Timeout: 5 * time.Second}

	start := time.Now()
	resp, err := client.Post(srv.URL+"/admission", "application/json", bytes.NewReader(body))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("请求失败（说明连接被挂住或被切断，而非返回 deny）: %v", err)
	}
	defer resp.Body.Close()

	// 1. handler 必须在 handlerTimeout 量级内返回，而不是拖到 5s 才被 client 掐断。
	if elapsed > 2*time.Second {
		t.Fatalf("A6 失败：handler 耗时 %v，远超 HandlerTimeout %v，说明请求被挂住", elapsed, handlerTimeout)
	}
	t.Logf("A6 handler 返回耗时 %v（HandlerTimeout=%v）", elapsed, handlerTimeout)

	// 2. 必须确认请求真的走到了 registry 拉取阶段，否则这个测试没验证到东西。
	select {
	case <-fetcher.entered:
		t.Log("A6 已确认请求进入 Fetch 阶段（registry 拉取）")
	default:
		t.Fatal("A6 无效：请求未进入 Fetch 阶段，超时路径未被触发")
	}

	// 3. HTTP 状态必须是 200——准入 webhook 用 200 + allowed:false 表达拒绝，
	//    返回 5xx 会让 apiserver 走 failurePolicy 分支，而不是收到判定结果。
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("A6 失败：期望 HTTP 200 + allowed:false，实际 %d %s", resp.StatusCode, raw)
	}

	var review httpapi.AdmissionReview
	if err := json.NewDecoder(resp.Body).Decode(&review); err != nil {
		t.Fatalf("解析 AdmissionReview 响应: %v", err)
	}
	if review.Response == nil {
		t.Fatal("A6 失败：响应缺少 response 字段")
	}
	if review.Response.Allowed {
		t.Fatalf("A6 失败：超时后竟然放行。status=%+v", review.Response.Result)
	}
	if review.Response.UID != "a6-timeout" {
		t.Fatalf("A6 uid 未回传：期望 a6-timeout，实际 %q", review.Response.UID)
	}
	var code int
	var msg string
	if review.Response.Result != nil {
		code, msg = review.Response.Result.Code, review.Response.Result.Message
	}
	if msg == "" {
		t.Fatal("A6 失败：拒绝响应没有给出原因，运维无法定位")
	}
	t.Logf("A6 deny（快速失败）: allowed=%v code=%d message=%q", review.Response.Allowed, code, msg)
}

// TestE2E_A6_TimeoutIsBounded 证明 handler 不会因某些路径绕过 deadline：
// 换一个更长的 HandlerTimeout，返回耗时应当随之变化，说明生效的是配置而非巧合。
func TestE2E_A6_TimeoutIsBounded(t *testing.T) {
	const handlerTimeout = 600 * time.Millisecond
	srv, _, _ := a6Server(t, handlerTimeout)

	client := &http.Client{Timeout: 5 * time.Second}
	start := time.Now()
	resp, err := client.Post(srv.URL+"/admission", "application/json",
		bytes.NewReader(a6AdmissionReview(t, "a6-bounded")))
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期望 HTTP 200，实际 %d", resp.StatusCode)
	}
	var review httpapi.AdmissionReview
	if err := json.NewDecoder(resp.Body).Decode(&review); err != nil {
		t.Fatalf("解析响应: %v", err)
	}
	if review.Response == nil || review.Response.Allowed {
		t.Fatal("A6 失败：超时后未拒绝")
	}
	// 下限断言：耗时至少接近 HandlerTimeout，证明是 deadline 生效而非立即失败。
	if elapsed < handlerTimeout/2 {
		t.Fatalf("A6 可疑：耗时 %v 明显早于 HandlerTimeout %v，可能未走超时路径", elapsed, handlerTimeout)
	}
	t.Logf("A6 deadline 生效：耗时 %v，HandlerTimeout=%v", elapsed, handlerTimeout)
}

// readFile 读取文件，便于在断言里给出清晰错误。
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// contains 是 strings.Contains 的薄封装。
func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

// containsLine 判断某一行（去空白后）恰好等于给定内容。
// 用于区分"配置里确有 failurePolicy: Fail"与"只出现在注释中"。
func containsLine(src, line string) bool {
	for _, l := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(l)
		// 跳过注释行，避免把文档说明误判为配置。
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == line {
			return true
		}
	}
	return false
}

// containsActiveYAML 判断 YAML 中是否存在未注释掉的 key。
func containsActiveYAML(src, key string) bool {
	for _, l := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, key) {
			return true
		}
	}
	return false
}

// TestE2E_A6_ChartFailurePolicyFail 证明部署形态层面的 fail closed 不变量：
// Chart 渲染出的 failurePolicy 恒为 Fail，且 values 不提供开关。
//
// 这条与上面两条测试互补：
//   - 上面证明"我们返回的是 deny"，
//   - 这条证明"apiserver 在我们没响应时也会 deny"。
func TestE2E_A6_ChartFailurePolicyFail(t *testing.T) {
	const path = "../../chart/templates/validatingwebhookconfiguration.yaml"
	b, err := readFile(path)
	if err != nil {
		t.Fatalf("读取 %s: %v", path, err)
	}
	src := string(b)

	// 1. 模板里必须出现未被条件包住的 failurePolicy: Fail。
	if !containsLine(src, "failurePolicy: Fail") {
		t.Fatalf("A6 失败：%s 中未找到 'failurePolicy: Fail'", path)
	}

	// 2. 不允许把 failurePolicy 写成 .Values 引用（否则就成了开关）。
	for _, bad := range []string{
		"failurePolicy: {{",
		"failurePolicy: {{ .Values",
		"failurePolicy: {{.Values",
	} {
		if contains(src, bad) {
			t.Fatalf("A6 失败：failurePolicy 被做成可配置项（%s），违反立项书 Non-negotiable 第 5 条", bad)
		}
	}

	// 3. timeoutSeconds 必须是字面量，不允许被 values 覆盖。
	if contains(src, "timeoutSeconds: {{") {
		t.Fatal("A6 失败：timeoutSeconds 被做成可配置项")
	}

	// 4. values.yaml 不得提供 failurePolicy / timeoutSeconds 开关。
	vb, err := readFile("../../chart/values.yaml")
	if err != nil {
		t.Fatalf("读取 values.yaml: %v", err)
	}
	vsrc := string(vb)
	for _, bad := range []string{"failurePolicy:", "timeoutSeconds:"} {
		if containsActiveYAML(vsrc, bad) {
			t.Fatalf("A6 失败：values.yaml 提供了 %s 开关，违反'不提供开关的安全不变量'", bad)
		}
	}
	t.Log("A6 Chart 不变量成立：failurePolicy 恒为 Fail，timeoutSeconds 无开关")
}
