package attest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// OCIFetcher 从 OCI Registry 拉取 attestation。
// 它是 Fetcher 接口的真实实现，go-containerregistry 的依赖被隔离在此文件中。
type OCIFetcher struct{}

func NewOCIFetcher() *OCIFetcher {
	return &OCIFetcher{}
}

// Fetch 根据完整 image 引用（如 "nginx@sha256:..."）拉取 SLSA provenance。
func (f *OCIFetcher) Fetch(ctx context.Context, imageRef string) (*Provenance, error) {
	ref, err := name.NewDigest(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parse image ref %q: %w", imageRef, err)
	}

	index, err := remote.Referrers(ref, remote.WithContext(ctx))
	if err != nil {
		if strings.Contains(err.Error(), "does not support the Referrers API") {
			return nil, ErrAttestationNotFound
		}
		return nil, fmt.Errorf("referrers for %s: %w", imageRef, err)
	}

	manifests, err := index.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("index manifest: %w", err)
	}

	for _, desc := range manifests.Manifests {
		if !isAttestationType(desc) {
			continue
		}

		img, err := index.Image(desc.Digest)
		if err != nil {
			continue
		}

		layers, err := img.Layers()
		if err != nil || len(layers) == 0 {
			continue
		}

		rc, err := layers[0].Compressed()
		if err != nil {
			continue
		}

		raw, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}

		var prov Provenance
		if err := json.Unmarshal(raw, &prov); err != nil {
			continue
		}
		prov.SLSALevel = inferSLSALevel(prov.BuildType, prov.Builder)
		return &prov, nil
	}

	return nil, ErrAttestationNotFound
}

func isAttestationType(desc v1.Descriptor) bool {
	artifactType := string(desc.ArtifactType)
	mediaType := string(desc.MediaType)
	return artifactType == "application/vnd.in-toto+json" ||
		strings.Contains(mediaType, "in-toto")
}
