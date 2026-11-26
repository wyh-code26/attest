package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 这些测试保证：身份 allowlist 文件写坏时，服务必须拒绝启动。
//
// 这条路径的危险在于"静默降级"——如果解析失败被吞掉、返回空 allowlist，
// 验签器就会收到 0 条规则。空 allowlist 要么拒绝所有镜像（全集群不可用），
// 要么被实现成"没有规则 = 不限制"（等于关掉身份校验）。
// 两种结果都是事故，所以必须在加载期就报错。

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identities.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadIdentitiesFromFile_Success(t *testing.T) {
	path := writeFile(t, `
identities:
  - issuer: https://token.actions.githubusercontent.com
    san_regexp: '^https://github\.com/wyh-code26/attest/'
  - issuer: https://accounts.google.com
    san_regexp: '^.*@example\.com$'
`)

	rules, err := LoadIdentitiesFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	if rules[0].Issuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("rules[0].Issuer = %q", rules[0].Issuer)
	}
	if rules[1].SANRegexp != `^.*@example\.com$` {
		t.Errorf("rules[1].SANRegexp = %q", rules[1].SANRegexp)
	}
}

func TestLoadIdentitiesFromFile_Errors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantMsg string
	}{
		{
			name:    "empty file",
			content: "",
			wantMsg: "no rules",
		},
		{
			name:    "no identities key",
			content: "something_else: true\n",
			wantMsg: "no rules",
		},
		{
			name:    "empty identities list",
			content: "identities: []\n",
			wantMsg: "no rules",
		},
		{
			name: "missing issuer",
			content: `identities:
  - san_regexp: '^x$'
`,
			wantMsg: "issuer is required",
		},
		{
			name: "missing san_regexp",
			content: `identities:
  - issuer: https://example.com
`,
			wantMsg: "san_regexp is required",
		},
		{
			name: "invalid regexp",
			content: `identities:
  - issuer: https://example.com
    san_regexp: '('
`,
			wantMsg: "invalid san_regexp",
		},
		{
			name:    "invalid yaml",
			content: "identities: [\n",
			wantMsg: "parse identities yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeFile(t, tt.content)
			_, err := LoadIdentitiesFromFile(path)
			if err == nil {
				t.Fatal("expected error, got nil — a broken allowlist must not silently load")
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error = %q, want contains %q", err, tt.wantMsg)
			}
		})
	}
}

func TestLoadIdentitiesFromFile_MissingFile(t *testing.T) {
	_, err := LoadIdentitiesFromFile(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "read identities file") {
		t.Errorf("error = %q, want read failure", err)
	}
}
