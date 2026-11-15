package attest

// Provenance 是 SLSA provenance 的极简结构。
// 我们只关心策略判定需要的字段，忽略绝大多数无关信息。
// 绝对不要在这里引入 protobuf 或 in-toto 官方库。
type Provenance struct {
	BuildType string `json:"buildType"`
	Builder   string `json:"builder"`
	SourceURI string `json:"sourceURI"`

	// SLSALevel 不由 JSON 直接提供，而是由 fetcher 在解析后根据
	// BuildType/Builder 推断填充。阶段三会换成更严谨的等级推导逻辑。
	SLSALevel int `json:"-"`
}

// inferSLSALevel 根据 BuildType 和 Builder 推断 SLSA 等级。
// 阶段二简化规则：
//   - BuildType 是 "https://slsa.dev/provenance/v1" 且 Builder 是已知托管构建服务 → L3
//   - BuildType 是 "https://slsa.dev/provenance/v1" → L2
//   - 其他 → L1
func inferSLSALevel(buildType, builder string) int {
	const slsaV1 = "https://slsa.dev/provenance/v1"
	knownBuilders := []string{
		"https://github.com/actions/runner",
		"https://cloudbuild.googleapis.com/GoogleHostedWorker",
		"https://tekton.dev/chains/v2",
	}
	if buildType == slsaV1 {
		for _, b := range knownBuilders {
			if builder == b {
				return 3
			}
		}
		return 2
	}
	return 1
}
