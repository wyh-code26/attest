package attest

import (
	"context"
	"fmt"
)

type FakeFetcher struct {
	// 用 map 模拟 registry 里的数据：key 是 image digest
	data map[string]*Provenance
}

func NewFakeFetcher(data map[string]*Provenance) *FakeFetcher {
	return &FakeFetcher{data: data}
}

func (f *FakeFetcher) Fetch(ctx context.Context, imageDigest string) (*Provenance, error) {
	p, ok := f.data[imageDigest]
	if !ok {
		// 注意：这里必须返回特定的错误，比如 ErrAttestationNotFound，
		// 以便上层 handler 区分“没有证明”和“网络错误”。
		return nil, ErrAttestationNotFound
	}
	return p, nil
}

// 预定义错误
var ErrAttestationNotFound = fmt.Errorf("attestation not found")
