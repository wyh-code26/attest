package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdmissionHandler_Allow(t *testing.T) {
	h := AdmissionHandler(discardLogger())

	body := `{
		"apiVersion":"admission.k8s.io/v1",
		"kind":"AdmissionReview",
		"request":{
			"uid":"test-uid-123",
			"kind":{"group":"","version":"v1","kind":"Pod"},
			"namespace":"default",
			"name":"test-pod",
			"operation":"CREATE",
			"object":{}
		}
	}`

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Response == nil {
		t.Fatal("response is nil")
	}
	if !resp.Response.Allowed {
		t.Errorf("allowed = false, want true")
	}
	if resp.Response.UID != "test-uid-123" {
		t.Errorf("uid = %q", resp.Response.UID)
	}
}

func TestAdmissionHandler_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	AdmissionHandler(discardLogger()).ServeHTTP(w, httptest.NewRequest("GET", "/admission", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestAdmissionHandler_InvalidJSON(t *testing.T) {
	w := httptest.NewRecorder()
	AdmissionHandler(discardLogger()).ServeHTTP(w,
		httptest.NewRequest("POST", "/admission", bytes.NewBufferString("not json")))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAdmissionHandler_MissingRequest(t *testing.T) {
	body := `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}`
	w := httptest.NewRecorder()
	AdmissionHandler(discardLogger()).ServeHTTP(w,
		httptest.NewRequest("POST", "/admission", bytes.NewBufferString(body)))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAdmissionRequest_GetObjectBytes(t *testing.T) {
	tests := []struct {
		name    string
		req     AdmissionRequest
		want    string
		wantErr bool
	}{
		{
			name: "object present",
			req:  AdmissionRequest{Object: json.RawMessage(`{"spec":{}}`)},
			want: `{"spec":{}}`,
		},
		{
			name: "raw fallback",
			req:  AdmissionRequest{Raw: json.RawMessage(`eyJzcGVjIjp7fX0=`)}, // base64 of {"spec":{}}
			want: `{"spec":{}}`,
		},
		{
			name:    "neither",
			req:     AdmissionRequest{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.req.GetObjectBytes()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
