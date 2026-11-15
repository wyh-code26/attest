package attest

import "context"

// Fetcher 定义了获取镜像 provenance 的能力。
// 真实实现由 go-containerregistry 提供，测试由 FakeFetcher 提供。
type Fetcher interface {
	Fetch(ctx context.Context, imageDigest string) (*Provenance, error)
}
