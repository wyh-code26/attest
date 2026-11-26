package attest

import (
	"context"

	"github.com/wyh-code26/attest/internal/verify"
)

// Fetcher 定义了获取镜像 provenance 的能力。
// 输入是完整的 OCI 引用（如 "nginx@sha256:..."），
// 因为只有 digest 无法定位 registry 和 repository。
type Fetcher interface {
	Fetch(ctx context.Context, imageRef string) (*Attestation, error)
}

// Attestation 是一次证明拉取的完整结果。
//
// 为什么要把两份数据分开装：
//   - Identity 是从签名证书扩展里提取、经密码学背书的字段，是**策略判定的唯一依据**；
//   - Provenance 是 payload 里的原始内容，推送方可以随便填，
//     只保留给审计日志留痕，任何判定逻辑都不得读取它。
//
// 把它们放进同一个结构体而不是让调用方各拿一份，是为了强制调用方
// 在同一个位置同时看到两者的区别，避免有人顺手读了 Provenance.Builder。
type Attestation struct {
	// Identity 是已认证的构建者身份。Verifier 为 nil（开发模式）时为 nil。
	Identity *verify.VerifiedIdentity

	// Provenance 是未认证的原始 payload 解析结果，仅用于审计与排障。
	// 不可用于任何安全判定。
	Provenance *Provenance
}
