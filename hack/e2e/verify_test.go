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

// TestWriteFixture 演示并验证：测试用自签信任根可以被写出并重新加载。
//
// 写入位置是 t.TempDir()，不是 hack/e2e/testdata/。理由：
// 每次 newPKI() 都会生成全新的随机密钥，把它写进版本库会让
// `go test ./...` 每次都留下一个内容不同的工作区变更——
// 与"测试不应污染工作区"冲突，且该文件没有任何读取方（e2e 运行时
// 在 t.TempDir() 里自已现生成信任根）。
func TestWriteFixture(t *testing.T) {
	dir := t.TempDir()
	p, err := newPKI()
	if err != nil {
		t.Fatalf("生成测试 PKI: %v", err)
	}
	root, err := p.trustedRootJSON()
	if err != nil {
		t.Fatalf("生成 trusted_root.json: %v", err)
	}
	path := filepath.Join(dir, "trusted_root.json")
	if err := os.WriteFile(path, root, 0o644); err != nil {
		t.Fatalf("写入 %s: %v", path, err)
	}

	// 写出去的文件必须能被生产加载器读回，否则这个演示无意义。
	tm, err := verify.NewFileTrustMaterial(path)
	if err != nil {
		t.Fatalf("重新加载 %s: %v", path, err)
	}
	if tm == nil {
		t.Fatal("重新加载返回 nil")
	}
	t.Logf("已写入临时目录 %s (%d bytes)，并可被生产加载器读回", path, len(root))
}
