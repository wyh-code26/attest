package verify

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// TrustMaterialProvider 管理信任根的获取与更新。
//
// 生产实现应定期从 Sigstore TUF 仓库拉取（阶段五），
// 开发/测试使用 FileTrustMaterial。
//
// 热更新的关键契约：
//   - Get 必须返回"当前生效"的信任根，不能阻塞。
//   - Refresh 失败时保留旧值，不能清空——清空等于"无信任根"，所有验签都会失败。
type TrustMaterialProvider interface {
	Get(ctx context.Context) (root.TrustedMaterial, error)
	Refresh(ctx context.Context) error
}

// FileTrustMaterial 从本地文件加载信任根。
// Refresh 重新读取同一路径，可用于配合定期拉取脚本更新文件。
type FileTrustMaterial struct {
	path string

	mu     sync.RWMutex
	cached root.TrustedMaterial
}

func NewFileTrustMaterial(path string) (*FileTrustMaterial, error) {
	p := &FileTrustMaterial{path: path}
	if err := p.Refresh(context.Background()); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *FileTrustMaterial) Get(_ context.Context) (root.TrustedMaterial, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.cached == nil {
		return nil, errors.New("trusted material not loaded")
	}
	return p.cached, nil
}

// Refresh 重新读取文件。
// 失败时保留旧的 cached 值，只返回错误——上层应记日志和指标，
// 但不能因此让服务停止验签。
func (p *FileTrustMaterial) Refresh(_ context.Context) error {
	tr, err := root.NewTrustedRootFromPath(p.path)
	if err != nil {
		return fmt.Errorf("load trusted root from %s: %w", p.path, err)
	}
	p.mu.Lock()
	p.cached = tr
	p.mu.Unlock()
	return nil
}
