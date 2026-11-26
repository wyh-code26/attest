package attest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/wyh-code26/attest/internal/verify"
)

func startTestRegistry(t *testing.T, withReferrers bool) string {
	t.Helper()
	s := httptest.NewServer(registry.New(registry.WithReferrersSupport(withReferrers)))
	t.Cleanup(s.Close)
	return strings.TrimPrefix(s.URL, "http://")
}

func pushBaseImage(t *testing.T, registryHost, repo string) (name.Digest, v1.Image) {
	t.Helper()
	img, err := random.Image(1024, 1)
	if err != nil {
		t.Fatalf("random image: %v", err)
	}
	tagRef, err := name.ParseReference(registryHost+"/"+repo+":latest", name.Insecure)
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	if err := remote.Write(tagRef, img); err != nil {
		t.Fatalf("push base image: %v", err)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	digestRef, err := name.NewDigest(registryHost+"/"+repo+"@"+digest.String(), name.Insecure)
	if err != nil {
		t.Fatalf("new digest ref: %v", err)
	}
	return digestRef, img
}

// pushAttestation 推送一个绑定到 baseDigest 的 in-toto attestation。
//
// 关键：不改 manifest 的 mediaType（保持标准 OCI image manifest），
// 只用 annotation 标识 in-toto。原因是 v0.22.1 的 remoteIndex 依赖
// mediaType 判断 manifest 类型，改成 in-toto 会导致 panic。
func pushAttestation(t *testing.T, registryHost, repo string, baseDigest v1.Hash, prov *Provenance) {
	t.Helper()
	raw, err := json.Marshal(prov)
	if err != nil {
		t.Fatalf("marshal provenance: %v", err)
	}
	layer := static.NewLayer(raw, types.MediaType("application/vnd.in-toto+json"))
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	img = mutate.Annotations(img, map[string]string{
		"org.opencontainers.artifact.type": "application/vnd.in-toto+json",
	}).(v1.Image)
	img = mutate.Subject(img, v1.Descriptor{Digest: baseDigest}).(v1.Image)

	attTag, err := name.ParseReference(registryHost+"/"+repo+":att-"+baseDigest.Hex[:8], name.Insecure)
	if err != nil {
		t.Fatalf("parse attestation tag: %v", err)
	}
	if err := remote.Write(attTag, img); err != nil {
		t.Fatalf("push attestation: %v", err)
	}
}

func TestOCIFetcher_Success(t *testing.T) {
	host := startTestRegistry(t, true)
	digestRef, baseImg := pushBaseImage(t, host, "test/with-att")
	baseDigest, _ := baseImg.Digest()

	want := &Provenance{
		BuildType: "https://slsa.dev/provenance/v1",
		Builder:   "https://github.com/actions/runner",
		SourceURI: "https://github.com/wyh-code26/attest",
	}
	pushAttestation(t, host, "test/with-att", baseDigest, want)

	// 注入一个返回固定身份的 verifier。
	// 这个测试要验证的正是分离：Identity 来自 verifier（证书），
	// Provenance 来自 payload，两者互不影响。
	certIdentity := &verify.VerifiedIdentity{
		Issuer:         "https://token.actions.githubusercontent.com",
		BuildSignerURI: "https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1.0.0",
		SourceRepoURI:  "https://github.com/acme/app",
		BuildConfigURI: "https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1.0.0",
		RunnerEnv:      verify.RunnerEnvGitHubHosted,
	}

	f := NewOCIFetcher(WithInsecure(), WithVerifier(&stubVerifier{id: certIdentity}))
	got, err := f.Fetch(context.Background(), digestRef.Name())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.Identity == nil {
		t.Fatal("Identity must be populated when a verifier is injected")
	}
	if got.Identity.SourceRepoURI != certIdentity.SourceRepoURI {
		t.Errorf("Identity.SourceRepoURI = %q, want %q", got.Identity.SourceRepoURI, certIdentity.SourceRepoURI)
	}
	if got.Identity.SLSALevel() != verify.SLSALevel3 {
		t.Errorf("SLSALevel = %d, want %d", got.Identity.SLSALevel(), verify.SLSALevel3)
	}
	// payload 侧只用于审计。
	if got.Provenance == nil {
		t.Fatal("Provenance must still be populated for audit")
	}
	if got.Provenance.Builder != want.Builder {
		t.Errorf("Provenance.Builder = %q, want %q", got.Provenance.Builder, want.Builder)
	}
}

// TestOCIFetcher_VerifierRejectionFailsFetch 验证验签失败时整个 Fetch 失败。
// 关键点：不能"跳过这一条找下一条"——攻击者可以在同一镜像上附加多条证明，
// 只要一条有效就绕过。
func TestOCIFetcher_VerifierRejectionFailsFetch(t *testing.T) {
	host := startTestRegistry(t, true)
	digestRef, baseImg := pushBaseImage(t, host, "test/bad-sig")
	baseDigest, _ := baseImg.Digest()

	pushAttestation(t, host, "test/bad-sig", baseDigest, &Provenance{
		BuildType: "https://slsa.dev/provenance/v1",
		Builder:   "https://github.com/actions/runner",
	})

	f := NewOCIFetcher(WithInsecure(), WithVerifier(&stubVerifier{err: errors.New("bad signature")}))
	_, err := f.Fetch(context.Background(), digestRef.Name())
	if err == nil {
		t.Fatal("verifier rejection must fail the whole fetch")
	}
	if !strings.Contains(err.Error(), "bad signature") {
		t.Errorf("error should wrap verifier error, got %v", err)
	}
}

// stubVerifier 是测试用的验签器：不验密码学，只按预设返回。
type stubVerifier struct {
	id  *verify.VerifiedIdentity
	err error
}

func (s *stubVerifier) Verify(_ context.Context, _ []byte, _ string) (*verify.VerifiedIdentity, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.id, nil
}

func TestOCIFetcher_NoAttestation(t *testing.T) {
	host := startTestRegistry(t, true)
	digestRef, _ := pushBaseImage(t, host, "test/bare")

	f := NewOCIFetcher(WithInsecure())
	_, err := f.Fetch(context.Background(), digestRef.Name())
	if !errors.Is(err, ErrAttestationNotFound) {
		t.Errorf("expected ErrAttestationNotFound, got %v", err)
	}
}

func TestOCIFetcher_RegistryWithoutReferrers(t *testing.T) {
	host := startTestRegistry(t, false)
	digestRef, _ := pushBaseImage(t, host, "test/old-registry")

	f := NewOCIFetcher(WithInsecure())
	_, err := f.Fetch(context.Background(), digestRef.Name())
	if !errors.Is(err, ErrAttestationNotFound) {
		t.Errorf("expected ErrAttestationNotFound, got %v", err)
	}
}

func TestOCIFetcher_InvalidRef(t *testing.T) {
	f := NewOCIFetcher()
	_, err := f.Fetch(context.Background(), "not-a-valid-ref")
	if err == nil {
		t.Fatal("expected error for invalid ref")
	}
}

// ---- H4: registry 白名单（SSRF 防护） ----

func TestOCIFetcher_RegistryNotAllowed(t *testing.T) {
	host := startTestRegistry(t, true)
	digestRef, baseImg := pushBaseImage(t, host, "test/allowlist")
	baseDigest, _ := baseImg.Digest()
	pushAttestation(t, host, "test/allowlist", baseDigest, &Provenance{
		BuildType: "https://slsa.dev/provenance/v1",
		Builder:   "https://github.com/actions/runner",
	})

	// 白名单里只放一个不相关的 host，本地测试 registry 必须被拒。
	f := NewOCIFetcher(WithInsecure(), WithAllowedRegistries("ghcr.io", "registry.k8s.io"))
	_, err := f.Fetch(context.Background(), digestRef.Name())
	if !errors.Is(err, ErrRegistryNotAllowed) {
		t.Fatalf("expected ErrRegistryNotAllowed, got %v", err)
	}
}

func TestOCIFetcher_RegistryAllowlisted(t *testing.T) {
	host := startTestRegistry(t, true)
	digestRef, baseImg := pushBaseImage(t, host, "test/allow-ok")
	baseDigest, _ := baseImg.Digest()
	pushAttestation(t, host, "test/allow-ok", baseDigest, &Provenance{
		BuildType: "https://slsa.dev/provenance/v1",
		Builder:   "https://github.com/actions/runner",
	})

	f := NewOCIFetcher(WithInsecure(), WithAllowedRegistries(host))
	if _, err := f.Fetch(context.Background(), digestRef.Name()); err != nil {
		t.Fatalf("allowlisted registry should pass, got %v", err)
	}
}

// 后缀不能匹配：evil-ghcr.io 不能被 "ghcr.io" 放行。
func TestOCIFetcher_AllowlistIsExactMatch(t *testing.T) {
	f := NewOCIFetcher(WithAllowedRegistries("ghcr.io"))
	ref, err := name.NewDigest("evil-ghcr.io/x/y@sha256:"+strings.Repeat("a", 64), name.Insecure)
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	if err := f.checkRegistry(ref); !errors.Is(err, ErrRegistryNotAllowed) {
		t.Fatalf("expected ErrRegistryNotAllowed for suffix trick, got %v", err)
	}
}

// ---- H4: attestation 体积上限（内存放大防护） ----

func TestOCIFetcher_AttestationTooLarge(t *testing.T) {
	host := startTestRegistry(t, true)
	digestRef, baseImg := pushBaseImage(t, host, "test/too-big")
	baseDigest, _ := baseImg.Digest()

	// 发一个远大于上限的 provenance。
	pushAttestation(t, host, "test/too-big", baseDigest, &Provenance{
		BuildType: "https://slsa.dev/provenance/v1",
		Builder:   "https://github.com/actions/runner",
		SourceURI: strings.Repeat("x", 8192),
	})

	f := NewOCIFetcher(WithInsecure(), WithMaxAttestationBytes(64))
	_, err := f.Fetch(context.Background(), digestRef.Name())
	if !errors.Is(err, ErrAttestationTooLarge) {
		t.Fatalf("expected ErrAttestationTooLarge, got %v", err)
	}
}
