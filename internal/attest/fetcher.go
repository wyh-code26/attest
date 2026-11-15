package attest

import "context"

// Fetcher 定义了获取镜像 provenance 的能力。
// 输入是完整的 OCI 引用（如 "nginx@sha256:..."），
// 因为只有 digest 无法定位 registry 和 repository。
type Fetcher interface {
	Fetch(ctx context.Context, imageRef string) (*Provenance, error)
}
