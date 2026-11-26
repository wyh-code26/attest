package attest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/wyh-code26/attest/internal/verify"
)

// DefaultMaxAttestationBytes 是单个 attestation layer 允许解压后的最大字节数。
//
// 为什么必须有上限：attestation 内容来自不受信任的 registry，
// io.ReadAll 无上限意味着恶意 registry 可以用高压缩比 payload 打爆准入服务内存。
// 准入服务在 failurePolicy: Fail 下挂掉 = 全集群无法创建 Pod，这是可被利用的 DoS 面。
// 4 MiB 对真实 SLSA provenance（通常几 KB 到几十 KB）留了足够余量。
const DefaultMaxAttestationBytes int64 = 4 << 20

// ErrRegistryNotAllowed 表示镜像所在的 registry 不在白名单内。
// 白名单存在的意义：准入服务会主动向镜像引用里的 host 建立出站连接，
// 若不加限制，任何能创建 Pod 的用户都能借准入服务探测内网（SSRF）。
var ErrRegistryNotAllowed = errors.New("image registry not allowed")

// ErrAttestationTooLarge 表示 attestation layer 超过大小上限。
// 单独成一个错误类型，因为它属于"拒绝服务防护触发"而不是"没有证明"，
// 两者在 metrics 和排障语义上必须可区分。
var ErrAttestationTooLarge = errors.New("attestation layer exceeds size limit")

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

	// allowedRegistries 是允许访问的 registry host 白名单（精确匹配 ref.Context().RegistryStr()）。
	// 为空表示不限制——仅限开发模式，生产必须显式配置。
	allowedRegistries map[string]struct{}

	// maxAttestationBytes 是单 layer 读取上限，0 表示使用 DefaultMaxAttestationBytes。
	maxAttestationBytes int64
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

// WithAllowedRegistries 设置 registry 白名单。
// host 需与镜像引用里的 registry 段完全一致（如 "ghcr.io"、"registry.k8s.io"），
// 刻意不做后缀匹配——后缀匹配会让 "evil-ghcr.io" 命中 "ghcr.io"。
func WithAllowedRegistries(hosts ...string) Option {
	return func(f *OCIFetcher) {
		f.allowedRegistries = make(map[string]struct{}, len(hosts))
		for _, h := range hosts {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			f.allowedRegistries[strings.ToLower(h)] = struct{}{}
		}
	}
}

// WithMaxAttestationBytes 覆盖单个 attestation layer 的读取上限。
func WithMaxAttestationBytes(n int64) Option {
	return func(f *OCIFetcher) {
		f.maxAttestationBytes = n
	}
}

// WithTransport 显式注入 HTTP transport。
// 生产必须传一个带超时和连接数上限的 transport：remote 默认 client 无整体超时，
// 恶意 registry 可以用慢速响应把请求挂到 ctx deadline 才释放。
func WithTransport(t http.RoundTripper) Option {
	return func(f *OCIFetcher) {
		f.remoteOpts = append(f.remoteOpts, remote.WithTransport(t))
	}
}

func NewOCIFetcher(opts ...Option) *OCIFetcher {
	f := &OCIFetcher{}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// checkRegistry 校验镜像引用里的 registry 是否在白名单内。
func (f *OCIFetcher) checkRegistry(ref name.Digest) error {
	if len(f.allowedRegistries) == 0 {
		return nil
	}
	host := strings.ToLower(ref.Context().RegistryStr())
	if _, ok := f.allowedRegistries[host]; !ok {
		return fmt.Errorf("%w: %q", ErrRegistryNotAllowed, host)
	}
	return nil
}

// effectiveMaxBytes 返回实际生效的读取上限。
func (f *OCIFetcher) effectiveMaxBytes() int64 {
	if f.maxAttestationBytes > 0 {
		return f.maxAttestationBytes
	}
	return DefaultMaxAttestationBytes
}

func (f *OCIFetcher) Fetch(ctx context.Context, imageRef string) (*Attestation, error) {
	ref, err := name.NewDigest(imageRef, f.nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("parse image ref %q: %w", imageRef, err)
	}
	// 白名单校验必须在任何出站连接之前。
	if err := f.checkRegistry(ref); err != nil {
		return nil, err
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
		// 多读 1 字节用于判定"是否超限"：恰好等于上限的内容应被接受，
		// 只有读满 limit+1 才说明确实越界。
		limit := f.effectiveMaxBytes()
		raw, err := io.ReadAll(io.LimitReader(rc, limit+1))
		rc.Close()
		if err != nil {
			continue
		}
		if int64(len(raw)) > limit {
			// 超限是主动防护触发，不能 continue 到下一层——
			// 否则攻击者只需在列表前面塞一个大 payload 就能拖慢每次判定。
			return nil, fmt.Errorf("%w: limit %d bytes", ErrAttestationTooLarge, limit)
		}

		// 验签必须在 Unmarshal 之前。
		// 如果验签失败，整个 Fetch 失败——不能"跳过这一条找下一条"，
		// 因为攻击者可以在同一个镜像上附加多条证明，其中一条有效即可绕过。
		//
		// verifier 返回的 VerifiedIdentity 来自签名证书扩展，是策略层唯一可信的事实。
		// 下面从 payload 解析出的 Provenance 仅供审计，两者绝不混用。
		var identity *verify.VerifiedIdentity
		if f.verifier != nil {
			id, err := f.verifier.Verify(ctx, raw, digest)
			if err != nil {
				return nil, fmt.Errorf("verify attestation: %w", err)
			}
			identity = id
		}

		var prov Provenance
		if err := json.Unmarshal(raw, &prov); err != nil {
			continue
		}
		prov.SLSALevel = inferSLSALevel(prov.BuildType, prov.Builder)
		return &Attestation{Identity: identity, Provenance: &prov}, nil
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
