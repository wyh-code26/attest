package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wyh-code26/attest/internal/verify"
)

// writeTrustRoot 把测试信任根写到临时文件，模拟生产部署。
func writeTrustRoot(t *testing.T, p *pki) string {
	t.Helper()
	js, err := p.trustedRootJSON()
	if err != nil {
		t.Fatalf("trustedRootJSON: %v", err)
	}
	path := filepath.Join(t.TempDir(), "trusted_root.json")
	if err := os.WriteFile(path, js, 0o600); err != nil {
		t.Fatalf("write trust root: %v", err)
	}
	return path
}

// TestVerifyRealBundle 用生产验证器验一份自签 bundle。
func TestVerifyRealBundle(t *testing.T) {
	p, err := newPKI()
	if err != nil {
		t.Fatal(err)
	}
	const imageDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

	att, err := p.issueAttestation(issueOptions{SubjectDigest: imageDigest})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	tm, err := verify.NewFileTrustMaterial(writeTrustRoot(t, p))
	if err != nil {
		t.Fatalf("trust material: %v", err)
	}
	v, err := verify.NewSigstoreVerifier(tm, []verify.IdentityRule{{
		Issuer:    fulcioIssuer,
		SANRegexp: "^" + testSAN + "$",
	}})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	id, err := v.Verify(t.Context(), att.BundleJSON, imageDigest)
	if err != nil {
		t.Fatalf("Verify FAILED: %v", err)
	}
	t.Logf("verified identity: issuer=%s signer=%s level=%d",
		id.Issuer, id.BuildSignerURI, id.SLSALevel())
}

// TestWriteFixture 把测试信任根写入 hack/e2e/testdata/，
// 使 fixture 进入版本库、可复现，且不被 Docker 镜像复制。
func TestWriteFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过 fixture 写入")
	}
	dir := filepath.Join("testdata")
	p, err := newPKI()
	if err != nil {
		t.Fatalf("生成测试 PKI: %v", err)
	}
	root, err := p.trustedRootJSON()
	if err != nil {
		t.Fatalf("生成 trusted_root.json: %v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("创建 testdata: %v", err)
	}
	path := filepath.Join(dir, "trusted_root.json")
	if err := os.WriteFile(path, root, 0o644); err != nil {
		t.Fatalf("写入 %s: %v", path, err)
	}
	t.Logf("已写入 %s (%d bytes)", path, len(root))
}
