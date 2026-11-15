package attest

import (
	"context"
	"errors"
)

// ErrAttestationNotFound 表示 registry 里没有该镜像的 attestation。
// 上层用 errors.Is 判断，区分"没有证明"和"网络错误"。
var ErrAttestationNotFound = errors.New("attestation not found")

// FakeFetcher 是测试用的 Fetcher 实现，从内存 map 返回数据。
type FakeFetcher struct {
	data map[string]*Provenance
}

func NewFakeFetcher(data map[string]*Provenance) *FakeFetcher {
	return &FakeFetcher{data: data}
}

func (f *FakeFetcher) Fetch(_ context.Context, imageDigest string) (*Provenance, error) {
	p, ok := f.data[imageDigest]
	if !ok {
		return nil, ErrAttestationNotFound
	}
	// 拷贝一份，避免调用方修改影响内部状态。
	cp := *p
	cp.SLSALevel = inferSLSALevel(cp.BuildType, cp.Builder)
	return &cp, nil
}
