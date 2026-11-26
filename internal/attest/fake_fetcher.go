package attest

import (
	"context"
	"errors"

	"github.com/wyh-code26/attest/internal/verify"
)

// ErrAttestationNotFound 表示 registry 里没有该镜像的 attestation。
var ErrAttestationNotFound = errors.New("attestation not found")

// FakeFetcher 是测试用的 Fetcher 实现，从内存 map 返回数据。
// map 的 key 是完整 image 引用（如 "nginx@sha256:..."）。
//
// 两个 map 的语义刻意分开：
//   - data 模拟 payload（未认证，供审计）；
//   - identities 模拟从证书提取出的已认证身份（供策略判定）。
//
// 需要验证"payload 被伪造但证书 OID 合法"这类场景时，两个 map 填不同内容即可。
type FakeFetcher struct {
	data       map[string]*Provenance
	identities map[string]*verify.VerifiedIdentity
	allowAll   bool
}

// NewFakeFetcher 构造只提供 payload 的 FakeFetcher。
// 此时 Identity 为 nil，任何依赖已认证身份的策略都会拒绝——这是有意的，
// 提醒调用方补上 identities。
func NewFakeFetcher(data map[string]*Provenance) *FakeFetcher {
	return &FakeFetcher{data: data}
}

// NewFakeFetcherWithIdentities 构造同时提供 payload 与已认证身份的 FakeFetcher。
func NewFakeFetcherWithIdentities(
	data map[string]*Provenance,
	identities map[string]*verify.VerifiedIdentity,
) *FakeFetcher {
	return &FakeFetcher{data: data, identities: identities}
}

func (f *FakeFetcher) Fetch(_ context.Context, imageRef string) (*Attestation, error) {
	if f.allowAll {
		return &Attestation{
			Identity: &verify.VerifiedIdentity{
				Issuer:         "https://token.actions.githubusercontent.com",
				BuildSignerURI: "https://github.com/wyh-code26/attest/.github/workflows/sign.yaml@refs/tags/v1",
				SourceRepoURI:  "https://github.com/wyh-code26/attest",
				BuildConfigURI: "https://github.com/wyh-code26/attest/.github/workflows/sign.yaml@refs/tags/v1",
				RunnerEnv:      "github-hosted",
			},
			Provenance: &Provenance{
				BuildType: "https://slsa.dev/provenance/v1",
				Builder:   "https://github.com/actions/runner",
				SLSALevel: 3,
			},
		}, nil
	}

	p, ok := f.data[imageRef]
	if !ok {
		return nil, ErrAttestationNotFound
	}
	cp := *p
	cp.SLSALevel = inferSLSALevel(cp.BuildType, cp.Builder)

	out := &Attestation{Provenance: &cp}
	// 显式处理"map 里登记了但值为 nil"，语义等同于"该镜像没有已认证身份"。
	// 直接解引用会 panic，而准入路径一旦 panic 就被 k8s 当成 webhook 故障，
	// 在 failurePolicy: Fail 下等价于全集群无法创建 Pod。
	if id, ok := f.identities[imageRef]; ok && id != nil {
		idCopy := *id
		out.Identity = &idCopy
	}
	return out, nil
}

// FakeFetcherAll 返回对任意镜像都成功的 FakeFetcher，用于准入链路测试。
//
// 它给出的身份是一个合规的 GitHub Actions 签名者（github-hosted + build config），
// 因此 SLSA 推导为 L3，能通过常见策略；要测拒绝路径请用 NewFakeFetcher*
// 构造数据，或直接让 Fetch 返回错误。
func FakeFetcherAll() *FakeFetcher {
	return &FakeFetcher{allowAll: true}
}
