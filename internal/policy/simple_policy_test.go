package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/wyh-code26/attest/internal/attest"
)

func TestSimplePolicy(t *testing.T) {
	tests := []struct {
		name           string
		rule           Rule
		prov           *attest.Provenance
		wantAllowed    bool
		wantReasonPart string
	}{
		{
			name:        "L3 with allowed builder",
			rule:        Rule{MinSLSA: 3, AllowedBuilders: []string{"https://github.com/actions/runner"}},
			prov:        &attest.Provenance{SLSALevel: 3, Builder: "https://github.com/actions/runner", BuildType: "https://slsa.dev/provenance/v1"},
			wantAllowed: true,
		},
		{
			name:           "L2 below L3 requirement",
			rule:           Rule{MinSLSA: 3},
			prov:           &attest.Provenance{SLSALevel: 2},
			wantAllowed:    false,
			wantReasonPart: "SLSA level 2 < required 3",
		},
		{
			name:           "builder not in allowlist",
			rule:           Rule{MinSLSA: 1, AllowedBuilders: []string{"https://github.com/actions/runner"}},
			prov:           &attest.Provenance{SLSALevel: 3, Builder: "https://evil.example.com"},
			wantAllowed:    false,
			wantReasonPart: "not in allowlist",
		},
		{
			name:           "build type not in allowlist",
			rule:           Rule{MinSLSA: 1, AllowedTypes: []string{"https://slsa.dev/provenance/v1"}},
			prov:           &attest.Provenance{SLSALevel: 3, BuildType: "https://other.dev"},
			wantAllowed:    false,
			wantReasonPart: "not in allowlist",
		},
		{
			name:           "nil provenance",
			rule:           Rule{MinSLSA: 1},
			prov:           nil,
			wantAllowed:    false,
			wantReasonPart: "nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewSimplePolicy(tt.rule)
			allowed, reason := p.Evaluate(context.Background(), tt.prov)
			if allowed != tt.wantAllowed {
				t.Errorf("allowed = %v, want %v (reason: %s)", allowed, tt.wantAllowed, reason)
			}
			if tt.wantReasonPart != "" && !strings.Contains(reason, tt.wantReasonPart) {
				t.Errorf("reason = %q, want contains %q", reason, tt.wantReasonPart)
			}
		})
	}
}
