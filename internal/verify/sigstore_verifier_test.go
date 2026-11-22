package verify

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 这个 Bundle 的 subject digest 是 sha512:76176ffa...
// 签名者 SAN 是 sigstore-js 的 release workflow。
const (
	testBundleDigest = "sha512:76176ffa33808b54602c7c35de5c6e9a4deb96066dba6533f50ac234f4f1f4c6b3527515dc17c06fbe2860030f410eee69ea20079bd3a2c6f3dcf3b329b10751"
	testBundleSAN    = `^https://github\.com/sigstore/sigstore-js/\.github/workflows/release\.yml@refs/heads/main$`
	testBundleIssuer = "https://token.actions.githubusercontent.com"
)

// findRepoRoot 从测试文件所在目录向上找到 go.mod 所在目录。
func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func realTestInputs(t *testing.T) (trustPath, bundlePath string) {
	t.Helper()
	root := findRepoRoot(t)
	trustPath = filepath.Join(root, "trusted_root.json")
	bundlePath = filepath.Join(root, "testdata", "bundle-provenance.json")
	if _, err := os.Stat(trustPath); err != nil {
		t.Skipf("trusted_root.json not available: %v", err)
	}
	if _, err := os.Stat(bundlePath); err != nil {
		t.Skipf("test bundle not available: %v", err)
	}
	return trustPath, bundlePath
}

func TestSigstoreVerifier_RealBundle_Valid(t *testing.T) {
	trustPath, bundlePath := realTestInputs(t)

	trust, err := NewFileTrustMaterial(trustPath)
	if err != nil {
		t.Fatalf("load trust: %v", err)
	}
	rules := []IdentityRule{{
		Issuer:    testBundleIssuer,
		SANRegexp: testBundleSAN,
	}}
	v, err := NewSigstoreVerifier(trust, rules)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	bundleJSON, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}

	err = v.Verify(context.Background(), bundleJSON, testBundleDigest)
	if err != nil {
		t.Fatalf("valid bundle should pass, got: %v", err)
	}
}

func TestSigstoreVerifier_RealBundle_WrongDigest(t *testing.T) {
	trustPath, bundlePath := realTestInputs(t)

	trust, err := NewFileTrustMaterial(trustPath)
	if err != nil {
		t.Fatalf("load trust: %v", err)
	}
	v, err := NewSigstoreVerifier(trust, []IdentityRule{{
		Issuer:    testBundleIssuer,
		SANRegexp: testBundleSAN,
	}})
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	bundleJSON, _ := os.ReadFile(bundlePath)

	wrongDigest := "sha512:" + strings.Repeat("0", 128)
	err = v.Verify(context.Background(), bundleJSON, wrongDigest)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("expected ErrDigestMismatch, got %v", err)
	}
}

func TestSigstoreVerifier_RealBundle_WrongIdentity(t *testing.T) {
	trustPath, bundlePath := realTestInputs(t)

	trust, err := NewFileTrustMaterial(trustPath)
	if err != nil {
		t.Fatalf("load trust: %v", err)
	}
	// 规则故意写成不匹配的 SAN。
	v, err := NewSigstoreVerifier(trust, []IdentityRule{{
		Issuer:    testBundleIssuer,
		SANRegexp: "^https://github\\.com/evil/repo/.*$",
	}})
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	bundleJSON, _ := os.ReadFile(bundlePath)

	err = v.Verify(context.Background(), bundleJSON, testBundleDigest)
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Errorf("expected ErrIdentityMismatch, got %v", err)
	}
}

func TestSigstoreVerifier_RealBundle_TamperedBundle(t *testing.T) {
	trustPath, bundlePath := realTestInputs(t)

	trust, err := NewFileTrustMaterial(trustPath)
	if err != nil {
		t.Fatalf("load trust: %v", err)
	}
	v, err := NewSigstoreVerifier(trust, []IdentityRule{{
		Issuer:    testBundleIssuer,
		SANRegexp: testBundleSAN,
	}})
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	bundleJSON, _ := os.ReadFile(bundlePath)

	// 篡改 Bundle：把 payload 的一个字节翻转。
	// DSSE payload 是 base64 的，翻转 base64 字符串中的一个字符即可让签名失效。
	tampered := []byte(string(bundleJSON))
	idx := strings.Index(string(tampered), `"payload":"`)
	if idx < 0 {
		t.Skip("cannot locate payload field")
	}
	payloadStart := idx + len(`"payload":"`)
	// 翻转 payload 开头第三个字符（避免破坏 JSON 结构）。
	orig := tampered[payloadStart+2]
	switch {
	case orig == 'A':
		tampered[payloadStart+2] = 'B'
	case orig == 'B':
		tampered[payloadStart+2] = 'A'
	default:
		tampered[payloadStart+2] = 'A'
	}

	err = v.Verify(context.Background(), tampered, testBundleDigest)
	if err == nil {
		t.Fatal("tampered bundle must fail, got nil")
	}
	// 篡改后错误可能是 SignatureInvalid 或 DigestMismatch（取决于篡改位置），
	// 只要不是 nil 就说明密码学验证拦住了。
	t.Logf("tampered bundle rejected: %v", err)
}
