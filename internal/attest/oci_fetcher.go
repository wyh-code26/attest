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

type OCIFetcher struct {
	nameOpts   []name.Option
	remoteOpts []remote.Option
}

type Option func(*OCIFetcher)

func WithInsecure() Option {
	return func(f *OCIFetcher) {
		f.nameOpts = append(f.nameOpts, name.Insecure)
	}
}

func NewOCIFetcher(opts ...Option) *OCIFetcher {
	f := &OCIFetcher{}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

func (f *OCIFetcher) Fetch(ctx context.Context, imageRef string) (*Provenance, error) {
	ref, err := name.NewDigest(imageRef, f.nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("parse image ref %q: %w", imageRef, err)
	}

	remoteOpts := append([]remote.Option{remote.WithContext(ctx)}, f.remoteOpts...)
	index, err := remote.Referrers(ref, remoteOpts...)
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

		// 绕开 remoteIndex.Image()：v0.22.1 在 Platform 为 nil 时会 panic。
		// 直接用 remote.Image 按 repo@digest 拉取。
		attRef, err := name.NewDigest(ref.Context().Name()+"@"+desc.Digest.String(), f.nameOpts...)
		if err != nil {
			continue
		}
		img, err := remote.Image(attRef, remoteOpts...)
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

// isAttestationType 判断 descriptor 是否指向 in-toto attestation。
//
// 兼容三种来源：
//  1. desc.ArtifactType（OCI 1.1 原生字段）
//  2. desc.MediaType（部分 registry 复制 artifactType 到 mediaType）
//  3. desc.Annotations["org.opencontainers.artifact.type"]（OCI 1.0 兼容写法）
func isAttestationType(desc v1.Descriptor) bool {
	if string(desc.ArtifactType) == "application/vnd.in-toto+json" {
		return true
	}
	if strings.Contains(string(desc.MediaType), "in-toto") {
		return true
	}
	if at, ok := desc.Annotations["org.opencontainers.artifact.type"]; ok &&
		strings.Contains(at, "in-toto") {
		return true
	}
	return false
}
