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

	f := NewOCIFetcher(WithInsecure())
	got, err := f.Fetch(context.Background(), digestRef.Name())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.Builder != want.Builder {
		t.Errorf("Builder = %q, want %q", got.Builder, want.Builder)
	}
	if got.SLSALevel != 3 {
		t.Errorf("SLSALevel = %d, want 3", got.SLSALevel)
	}
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
