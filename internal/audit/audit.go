// Package audit 记录准入决策的结构化审计日志。
//
// 输出格式：每行一个 JSON 对象（JSON Lines）。
// 阶段五可把 io.Writer 从 os.Stdout 换为 Loki/ES 的 client，无需改调用方。
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Event 是一次准入决策的完整审计记录。
type Event struct {
	Time      time.Time `json:"time"`
	RequestID string    `json:"request_id,omitempty"`
	UID       string    `json:"uid,omitempty"`
	Kind      string    `json:"kind,omitempty"`
	Namespace string    `json:"namespace,omitempty"`
	Name      string    `json:"name,omitempty"`
	Operation string    `json:"operation,omitempty"`

	Image  string `json:"image,omitempty"`
	Digest string `json:"digest,omitempty"`

	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`

	PolicyReason string `json:"policy_reason,omitempty"`

	// 以下字段来自**签名证书**（verify.VerifiedIdentity），是经密码学背书的真值，
	// 排查时应该看这几个。
	//
	// 注意：这里刻意没有 `builder` 字段。证书给的是 workflow 签名者 URI，
	// 叫 build_signer 才准确；如果还留一个 builder，就会和 payload 的
	// declared_builder 在同一个 JSON 里长得像同类东西，审计时极易混淆。
	SLSALevel   int    `json:"slsa_level,omitempty"`
	SourceRepo  string `json:"source_repo,omitempty"`
	BuildSigner string `json:"build_signer,omitempty"`
	RunnerEnv   string `json:"runner_env,omitempty"`

	// DeclaredBuilder / DeclaredBuildType 是 payload 自述的值，仅供参考。
	// 故意用 declared_ 前缀与上面区分，避免有人误把它们当作事实。
	DeclaredBuilder   string `json:"declared_builder,omitempty"`
	DeclaredBuildType string `json:"declared_build_type,omitempty"`
}

// Recorder 把事件以 JSON Lines 形式写入 w。线程安全。
type Recorder struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewRecorder(w io.Writer) *Recorder {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &Recorder{enc: enc}
}

// Record 写入一条审计事件。
// 返回 error 表示写入失败，调用方应记日志但不阻塞准入决策。
func (r *Recorder) Record(e Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.enc.Encode(e)
}
