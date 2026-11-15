package attest

// Provenance 是 SLSA provenance 的极简结构。
// 我们只关心策略判定需要的字段，忽略绝大多数无关信息。
// 绝对不要在这里引入 protobuf 或 in-toto 官方库。
type Provenance struct {
	BuildType string `json:"buildType"`
	Builder   string `json:"builder"`
	SourceURI string `json:"sourceURI"`
}
