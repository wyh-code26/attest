// Package metrics 实现零依赖的 Prometheus 文本格式指标。
//
// 不引入 prometheus/client_golang：项目只需要一个 counter，
// 手写文本格式的成本远低于引入一棵新的依赖树。
package metrics

import (
	"fmt"
	"net/http"
	"sync"
)

// Result 是准入决策的最终结果。
type Result string

const (
	ResultAllow                  Result = "allow"
	ResultDenyNoObject           Result = "deny_no_object"
	ResultDenyInvalidImage       Result = "deny_invalid_image"
	ResultDenyMissingAttestation Result = "deny_missing_attestation"
	ResultDenyFetchError         Result = "deny_fetch_error"
	ResultDenyPolicy             Result = "deny_policy"
	ResultErrorBadRequest        Result = "error_bad_request"
	ResultErrorMethodNotAllowed  Result = "error_method_not_allowed"
	ResultErrorInternal          Result = "error_internal"
)

var allResults = []Result{
	ResultAllow,
	ResultDenyNoObject,
	ResultDenyInvalidImage,
	ResultDenyMissingAttestation,
	ResultDenyFetchError,
	ResultDenyPolicy,
	ResultErrorBadRequest,
	ResultErrorMethodNotAllowed,
	ResultErrorInternal,
}

var knownResults = func() map[Result]struct{} {
	m := make(map[Result]struct{}, len(allResults))
	for _, r := range allResults {
		m[r] = struct{}{}
	}
	return m
}()

// Metrics 是准入决策计数器，线程安全。
type Metrics struct {
	mu      sync.Mutex
	counter map[Result]int64
}

func New() *Metrics {
	m := &Metrics{counter: make(map[Result]int64, len(allResults))}
	for _, r := range allResults {
		m.counter[r] = 0
	}
	return m
}

// Record 递增某个结果的计数。
// result 必须是预定义的 Result 常量，否则 panic。
func (m *Metrics) Record(result Result) {
	if _, ok := knownResults[result]; !ok {
		panic(fmt.Sprintf("metrics: unknown result %q", result))
	}
	m.mu.Lock()
	m.counter[result]++
	m.mu.Unlock()
}

// Handler 返回 /metrics 的 HTTP handler。
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		snapshot := make(map[Result]int64, len(m.counter))
		for k, v := range m.counter {
			snapshot[k] = v
		}
		m.mu.Unlock()

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintln(w, "# HELP attest_admission_requests_total Total admission review decisions, labeled by result.")
		fmt.Fprintln(w, "# TYPE attest_admission_requests_total counter")
		for _, r := range allResults {
			fmt.Fprintf(w, "attest_admission_requests_total{result=%q} %d\n", r, snapshot[r])
		}
	})
}

// Snapshot 返回当前计数的只读拷贝，供测试断言使用。
func (m *Metrics) Snapshot() map[Result]int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[Result]int64, len(m.counter))
	for k, v := range m.counter {
		out[k] = v
	}
	return out
}
