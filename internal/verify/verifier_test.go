package verify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

func TestNewSigstoreVerifier_RequiresTrustAndRules(t *testing.T) {
	tests := []struct {
		name  string
		trust TrustMaterialProvider
		rules []IdentityRule
	}{
		{"nil trust", nil, []IdentityRule{{Issuer: "x", SANRegexp: "y"}}},
		{"empty rules", &brokenTrust{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewSigstoreVerifier(tt.trust, tt.rules); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSigstoreVerifier_TrustUnavailableIsFailClosed(t *testing.T) {
	// 核心契约：信任根不可用时，Verify 必须返回 ErrSignatureInvalid，
	// 而不是"降级放行"。
	v, err := NewSigstoreVerifier(&brokenTrust{}, []IdentityRule{
		{Issuer: "https://example.com", SANRegexp: ".*"},
	})
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	id, err := v.Verify(context.Background(), []byte("{}"), "sha256:"+strings.Repeat("0", 64))
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("expected ErrSignatureInvalid, got %v", err)
	}
	if id != nil {
		t.Errorf("failed verification must not return an identity, got %+v", id)
	}
}

// brokenTrust 模拟"信任根不可用"。
type brokenTrust struct{}

func (b *brokenTrust) Get(_ context.Context) (root.TrustedMaterial, error) {
	return nil, errors.New("trust unavailable")
}

func (b *brokenTrust) Refresh(_ context.Context) error { return nil }
