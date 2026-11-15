package attest

import (
	"context"
	"errors"
)

// ErrAttestationNotFound 表示 registry 里没有该镜像的 attestation。
var ErrAttestationNotFound = errors.New("attestation not found")

// FakeFetcher 是测试用的 Fetcher 实现，从内存 map 返回数据。
// map 的 key 是完整 image 引用（如 "nginx@sha256:..."）。
type FakeFetcher struct {
	data map[string]*Provenance
}

func NewFakeFetcher(data map[string]*Provenance) *FakeFetcher {
	return &FakeFetcher{data: data}
}

func (f *FakeFetcher) Fetch(_ context.Context, imageRef string) (*Provenance, error) {
	p, ok := f.data[imageRef]
	if !ok {
		return nil, ErrAttestationNotFound
	}
	cp := *p
	cp.SLSALevel = inferSLSALevel(cp.BuildType, cp.Builder)
	return &cp, nil
}
