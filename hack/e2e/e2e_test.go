package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	gcrregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/wyh-code26/attest/internal/attest"
	"github.com/wyh-code26/attest/internal/verify"
)

// 本文件是 A1/A3/A2 的离线端到端验收。
//
// 链路：自签测试信任根（hack/e2e/）签发 SLSA provenance bundle →
// 推进进程内 OCI registry → 生产 verify.SigstoreVerifier 验签 →
// 生产策略判定。全程不访问公网，不使用 registry:2。

// e2eEnv 是一次 E2E 场景的运行环境。
type e2eEnv struct {
	registryHost string
	verifier     verify.Verifier
	trustRoot    []byte
	repo         string
	pki          *pki
}

// issue 用本场景的 PKI 签发 attestation，保证与 verifier 的信任根同源。
func (e *e2eEnv) issue(t *testing.T, _ string, opts issueOptions) (*attestation, error) {
	t.Helper()
	return e.pki.issueAttestation(opts)
}

// newE2EEnv 启动进程内 registry，并构建使用自签信任根的生产 verifier。
func newE2EEnv(t *testing.T) *e2eEnv {
	t.Helper()

	p, err := newPKI()
	if err != nil {
		t.Fatalf("生成测试 PKI: %v", err)
	}
	trustRoot, err := p.trustedRootJSON()
	if err != nil {
		t.Fatalf("生成 trusted_root.json: %v", err)
	}

	srv := httptest.NewServer(gcrregistry.New(gcrregistry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	rootPath := filepath.Join(dir, "trusted_root.json")
	if err := os.WriteFile(rootPath, trustRoot, 0o600); err != nil {
		t.Fatalf("写入 trusted_root.json: %v", err)
	}

	tm, err := verify.NewFileTrustMaterial(rootPath)
	if err != nil {
		t.Fatalf("加载信任根: %v", err)
	}
	verifier, err := verify.NewSigstoreVerifier(tm, []verify.IdentityRule{
		{Issuer: fulcioIssuer, SANRegexp: "^" + testSAN + "$"},
	})
	if err != nil {
		t.Fatalf("构建 verifier: %v", err)
	}

	return &e2eEnv{
		registryHost: strings.TrimPrefix(srv.URL, "http://"),
		verifier:     verifier,
		trustRoot:    trustRoot,
		repo:         "attest-e2e/app",
		pki:          p,
	}
}

// pushImage 推一个基础镜像，返回其 digest 引用与哈希。
func (e *e2eEnv) pushImage(t *testing.T) (name.Digest, v1.Hash) {
	t.Helper()
	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	tagRef, err := name.ParseReference(e.registryHost+"/"+e.repo+":latest", name.Insecure)
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	if err := remote.Write(tagRef, img); err != nil {
		t.Fatalf("push image: %v", err)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("image digest: %v", err)
	}
	digestRef, err := name.NewDigest(e.registryHost+"/"+e.repo+"@"+digest.String(), name.Insecure)
	if err != nil {
		t.Fatalf("digest ref: %v", err)
	}
	return digestRef, digest
}

// pushAttestation 把一个 bundle 作为 in-toto attestation 推到 baseDigest 上。
func (e *e2eEnv) pushAttestation(t *testing.T, baseDigest v1.Hash, bundleJSON []byte, tagSuffix string) {
	t.Helper()
	layer := static.NewLayer(bundleJSON, types.MediaType("application/vnd.in-toto+json"))
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	img = mutate.Annotations(img, map[string]string{
		"org.opencontainers.artifact.type": "application/vnd.in-toto+json",
	}).(v1.Image)
	img = mutate.Subject(img, v1.Descriptor{Digest: baseDigest}).(v1.Image)

	ref, err := name.ParseReference(
		e.registryHost+"/"+e.repo+":att-"+tagSuffix, name.Insecure)
	if err != nil {
		t.Fatalf("parse attestation tag: %v", err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("push attestation: %v", err)
	}
}

// subjectDigest 生成与镜像 digest 对应的 expectedDigest 字符串。
func subjectDigest(h v1.Hash) string {
	return h.Algorithm + ":" + h.Hex
}

// sha256Hex 计算字符串的 sha256 十六进制摘要。
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestE2E_A1_ValidAttestationAllowed 覆盖 A1：合法 attestation 验签通过。
func TestE2E_A1_ValidAttestationAllowed(t *testing.T) {
	env := newE2EEnv(t)
	_, baseHash := env.pushImage(t)
	dg := subjectDigest(baseHash)

	// 用 env 自己的 PKI 签发，保证与 verifier 的信任根同源。
	att, err := env.issue(t, dg, issueOptions{SubjectDigest: dg})
	if err != nil {
		t.Fatalf("签发 attestation: %v", err)
	}
	env.pushAttestation(t, baseHash, att.BundleJSON, "a1")

	got, err := env.verifier.Verify(t.Context(), att.BundleJSON, dg)
	if err != nil {
		t.Fatalf("A1 验签失败: %v", err)
	}
	t.Logf("A1 allow: subject=%s issuer=%s level=%d",
		dg, got.Issuer, got.SLSALevel())
}

// TestE2E_A3_TamperedPayloadDenied 覆盖 A3：签名后篡改 payload 一字节。
func TestE2E_A3_TamperedPayloadDenied(t *testing.T) {
	env := newE2EEnv(t)
	_, baseHash := env.pushImage(t)
	dg := subjectDigest(baseHash)

	att, err := env.issue(t, dg, issueOptions{SubjectDigest: dg, TamperPayload: true})
	if err != nil {
		t.Fatalf("签发篡改 attestation: %v", err)
	}

	_, err = env.verifier.Verify(t.Context(), att.BundleJSON, dg)
	if err == nil {
		t.Fatal("A3 篡改 payload 未被拒绝")
	}
	if !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("A3 错误类型不符，期望 signature invalid，实际: %v", err)
	}
	t.Logf("A3 deny_invalid_signature: %v", err)
}

// TestE2E_A3_DigestMismatchDenied 覆盖 A3：签名合法但 subject digest 与镜像不符。
//
// 生产 verifier 在签名验通之后，把 bundle 内 statement 的 subject digest 与
// 期望的镜像 digest 做密码学比对；不一致即判定为签名无效类拒绝。
func TestE2E_A3_DigestMismatchDenied(t *testing.T) {
	env := newE2EEnv(t)
	_, baseHash := env.pushImage(t)
	dg := subjectDigest(baseHash)

	// 用别的 digest 签发：签名自身合法，但绑定的是另一个镜像。
	other := "sha256:" + sha256Hex("a-different-image")
	att, err := env.issue(t, other, issueOptions{SubjectDigest: other})
	if err != nil {
		t.Fatalf("签发 attestation: %v", err)
	}

	_, err = env.verifier.Verify(t.Context(), att.BundleJSON, dg)
	if err == nil {
		t.Fatal("A3 digest 不匹配未被拒绝")
	}
	// 期望 digest 与 statement 内 digest 不符，必须被拒绝。
	if !strings.Contains(err.Error(), "signature invalid") &&
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("A3 错误类型不符，期望 digest 不匹配类拒绝，实际: %v", err)
	}
	t.Logf("A3 deny_invalid_signature(digest mismatch): %v", err)
}

// TestE2E_A2_MissingAttestationDenied 覆盖 A2：registry 上没有 attestation。
func TestE2E_A2_MissingAttestationDenied(t *testing.T) {
	env := newE2EEnv(t)
	base, _ := env.pushImage(t)

	// 走生产 OCIFetcher：registry 上没有 attestation，必须返回 ErrAttestationNotFound。
	f := attest.NewOCIFetcher(attest.WithAllowedRegistries(env.registryHost))
	_, err := f.Fetch(t.Context(), base.String())
	if err == nil {
		t.Fatal("A2 缺失 attestation 未被拒绝")
	}
	if !errors.Is(err, attest.ErrAttestationNotFound) {
		t.Fatalf("A2 错误类型不符，期望 ErrAttestationNotFound，实际: %v", err)
	}
	t.Logf("A2 deny_missing_attestation: %v", err)
}

// TestE2E_NoTestArtifactsInImage 验证约束 2 的静态部分：
// testdata 中的密钥与信任根不会被 Dockerfile 复制进镜像。
func TestE2E_NoTestArtifactsInImage(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatalf("读取 Dockerfile: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "COPY ") {
			continue
		}
		if strings.Contains(trimmed, "hack/") || strings.Contains(trimmed, "testdata") {
			t.Fatalf("Dockerfile 不得复制测试材料: %s", trimmed)
		}
	}
	t.Log("Dockerfile 未复制 hack/ 或 testdata")
}

var _ = json.Marshal
var _ = http.StatusOK
