package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// mustTrustRoot 把生成的 trusted_root.json 用生产同款加载器解析成
// TrustedMaterial，确保格式与线上一致。
func mustTrustRoot(t *testing.T, p *pki) root.TrustedMaterial {
	t.Helper()
	js, err := p.trustedRootJSON()
	if err != nil {
		t.Fatalf("trustedRootJSON: %v", err)
	}
	tr, err := root.NewTrustedRootFromJSON(js)
	if err != nil {
		t.Fatalf("parse trusted root: %v", err)
	}
	return tr
}

// TestTrustRootParses 确认生成的 trusted_root.json 能被 sigstore-go 解析。
func TestTrustRootParses(t *testing.T) {
	p, err := newPKI()
	if err != nil {
		t.Fatal(err)
	}
	js, err := p.trustedRootJSON()
	if err != nil {
		t.Fatalf("trustedRootJSON: %v", err)
	}
	t.Logf("trusted root size: %d bytes", len(js))

	if _, err := root.NewTrustedRootFromJSON(js); err != nil {
		t.Fatalf("NewTrustedRootFromJSON: %v", err)
	}
}

// TestSCTVerifies 确认内嵌 SCT 能通过 sigstore 的校验。
func TestSCTVerifies(t *testing.T) {
	p, err := newPKI()
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, err := p.issueLeafWithSCT(&leafKey.PublicKey)
	if err != nil {
		t.Fatalf("issueLeafWithSCT: %v", err)
	}

	err = verify.VerifySignedCertificateTimestamp(
		[][]*x509.Certificate{{leaf, p.intermediate, p.rootCert}}, 1,
		mustTrustRoot(t, p),
	)
	if err != nil {
		t.Fatalf("SCT verify FAILED: %v", err)
	}
	t.Log("SCT verified OK")
}

func mustTrustRootJSON(t *testing.T, p *pki) []byte {
	t.Helper()
	js, err := p.trustedRootJSON()
	if err != nil {
		t.Fatalf("trustedRootJSON: %v", err)
	}
	return js
}
