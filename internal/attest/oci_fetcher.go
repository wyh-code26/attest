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
	"github.com/wyh-code26/attest/internal/verify"
)

// OCIFetcher 从 OCI Registry 拉取 attestation。
//
// 验签契约：
//   - 如果注入了 Verifier，拉到 blob 后必须先验签，验签失败返回 verify.Err*。
//   - 验签通过后才 json.Unmarshal，保证解析的是已认证的数据。
//   - Verifier 为 nil 时跳过验签——这是开发模式的逃生舱，生产必须注入。
type OCIFetcher struct {
	nameOpts   []name.Option
	remoteOpts []remote.Option
	verifier   verify.Verifier
}

type Option func(*OCIFetcher)

func WithInsecure() Option {
	return func(f *OCIFetcher) {
		f.nameOpts = append(f.nameOpts, name.Insecure)
	}
}

func WithVerifier(v verify.Verifier) Option {
	return func(f *OCIFetcher) {
		f.verifier = v
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
	digest := ref.DigestStr()

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

		// 验签必须在 Unmarshal 之前。
		// 如果验签失败，整个 Fetch 失败——不能"跳过这一条找下一条"，
		// 因为攻击者可以在同一个镜像上附加多条证明，其中一条有效即可绕过。
		if f.verifier != nil {
			if err := f.verifier.Verify(ctx, raw, digest); err != nil {
				return nil, fmt.Errorf("verify attestation: %w", err)
			}
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
