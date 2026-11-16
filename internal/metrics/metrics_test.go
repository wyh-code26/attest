package metrics

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestMetrics_RecordAndSnapshot(t *testing.T) {
	m := New()
	m.Record(ResultAllow)
	m.Record(ResultAllow)
	m.Record(ResultDenyPolicy)

	snap := m.Snapshot()
	if snap[ResultAllow] != 2 {
		t.Errorf("allow = %d, want 2", snap[ResultAllow])
	}
	if snap[ResultDenyPolicy] != 1 {
		t.Errorf("deny_policy = %d, want 1", snap[ResultDenyPolicy])
	}
	if snap[ResultDenyFetchError] != 0 {
		t.Errorf("deny_fetch_error = %d, want 0", snap[ResultDenyFetchError])
	}
}

func TestMetrics_UnknownResultPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for unknown result")
		}
	}()
	New().Record(Result("bogus"))
}

func TestMetrics_Handler_Format(t *testing.T) {
	m := New()
	m.Record(ResultAllow)

	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))

	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "# TYPE attest_admission_requests_total counter") {
		t.Errorf("missing TYPE line:\n%s", body)
	}
	if !strings.Contains(body, `attest_admission_requests_total{result="allow"} 1`) {
		t.Errorf("missing allow sample:\n%s", body)
	}
	if !strings.Contains(body, `attest_admission_requests_total{result="deny_policy"} 0`) {
		t.Errorf("missing zero sample for deny_policy:\n%s", body)
	}
}

func TestMetrics_ConcurrentRecord(t *testing.T) {
	m := New()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Record(ResultAllow)
		}()
	}
	wg.Wait()
	if snap := m.Snapshot(); snap[ResultAllow] != 100 {
		t.Errorf("allow = %d, want 100", snap[ResultAllow])
	}
}
