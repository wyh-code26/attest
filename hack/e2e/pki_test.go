package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestIssueLeaf 确认自建 PKI 能签发合法的 Fulcio 风格证书，
// 且 SAN 与扩展可被 x509 正确解析。
func TestIssueLeaf(t *testing.T) {
	p, err := newPKI()
	if err != nil {
		t.Fatalf("newPKI: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := p.issueLeaf(&leafKey.PublicKey, nil)
	if err != nil {
		t.Fatalf("issueLeaf: %v", err)
	}

	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != testSAN {
		t.Fatalf("SAN mismatch: %v", leaf.URIs)
	}

	// 链校验：叶子 -> 中间 -> 根
	pool := x509.NewCertPool()
	pool.AddCert(p.rootCert)
	inter := x509.NewCertPool()
	inter.AddCert(p.intermediate)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("chain verify: %v", err)
	}

	// 扩展可读回
	var sawBuildConfig bool
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidBuildConfigURI) {
			sawBuildConfig = true
		}
	}
	if !sawBuildConfig {
		t.Fatal("build config extension missing")
	}
}

// TestSCTEncoding 确认 SCT 扩展能写进证书并被 x509 解析。
func TestSCTEncoding(t *testing.T) {
	p, err := newPKI()
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	leaf, err := p.issueLeafWithSCT(&leafKey.PublicKey)
	if err != nil {
		t.Fatalf("issueLeafWithSCT: %v", err)
	}

	var found bool
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidSCT) {
			found = true
		}
	}
	if !found {
		t.Fatal("SCT extension not embedded")
	}
}

var _ = pkix.Name{}
var _ = big.NewInt
var _ = time.Now
