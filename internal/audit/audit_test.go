package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func TestRecorder_WritesJSONLine(t *testing.T) {
	var buf bytes.Buffer
	rec := NewRecorder(&buf)

	ev := Event{
		RequestID: "req-1",
		UID:       "uid-1",
		Kind:      "Pod",
		Namespace: "default",
		Name:      "test-pod",
		Operation: "CREATE",
		Image:     "nginx@sha256:abc",
		Allowed:   false,
		Reason:    "deny_policy",
		Message:   "policy denied",
	}
	if err := rec.Record(ev); err != nil {
		t.Fatalf("Record: %v", err)
	}

	line := strings.TrimSpace(buf.String())
	var got Event
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("unmarshal: %v\nline: %s", err, line)
	}
	if got.RequestID != "req-1" {
		t.Errorf("RequestID = %q", got.RequestID)
	}
	if got.Allowed {
		t.Error("Allowed = true, want false")
	}
	if got.Reason != "deny_policy" {
		t.Errorf("Reason = %q", got.Reason)
	}
	if got.Time.IsZero() {
		t.Error("Time should be auto-filled")
	}
}

func TestRecorder_ConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	rec := NewRecorder(&buf)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = rec.Record(Event{RequestID: "r", Allowed: true, Reason: "allow"})
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 100 {
		t.Errorf("got %d lines, want 100", len(lines))
	}
	for i, line := range lines {
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Errorf("line %d invalid JSON: %v", i, err)
		}
	}
}
