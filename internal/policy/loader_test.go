package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileLoader_Success(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.yaml")
	content := `
min_slsa_level: 2
allowed_source_repositories:
  - "https://github.com/acme/app"
allowed_build_signer_regex:
  - '^https://github\\.com/acme/app/'
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewFileLoader(path)
	p, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sp, ok := p.(*SimplePolicy)
	if !ok {
		t.Fatalf("loaded policy is %T, want *SimplePolicy", p)
	}
	if sp.rule.MinSLSA != 2 {
		t.Errorf("MinSLSA = %d, want 2", sp.rule.MinSLSA)
	}
	if len(sp.rule.AllowedSourceRepositories) != 1 || sp.rule.AllowedSourceRepositories[0] != "https://github.com/acme/app" {
		t.Errorf("AllowedSourceRepositories = %v", sp.rule.AllowedSourceRepositories)
	}
	if len(sp.rule.AllowedBuildSignerRegex) != 1 {
		t.Errorf("AllowedBuildSignerRegex = %v", sp.rule.AllowedBuildSignerRegex)
	}
	// 加载期就应该预编译好正则。
	if len(sp.compiled.signerRes) != 1 {
		t.Errorf("signer regexes not compiled at load time: %d", len(sp.compiled.signerRes))
	}
}

func TestFileLoader_NotFound(t *testing.T) {
	loader := NewFileLoader("does-not-exist.yaml")
	_, err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestFileLoader_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.yaml")
	if err := os.WriteFile(path, []byte("not: valid: yaml: ["), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewFileLoader(path)
	_, err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid yaml")
	}
}

// TestFileLoader_InvalidRegexFailsAtStartup 验证坏策略在启动期被拦下，
// 而不是等到第一个镜像进来才暴露（那时要么全拒，要么 fail-open 放行）。
func TestFileLoader_InvalidRegexFailsAtStartup(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.yaml")
	content := "min_slsa_level: 1\nallowed_build_signer_regex:\n  - \"(\"\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewFileLoader(path)
	_, err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

// TestFileLoader_RealPolicyFile 验证仓库里实际的 policy.yaml 能被加载。
// 这份文件是部署时真正会用的，格式写错会导致服务起不来。
func TestFileLoader_RealPolicyFile(t *testing.T) {
	path := filepath.Join(findRepoRoot(t), "policy.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("policy.yaml not available: %v", err)
	}

	p, err := NewFileLoader(path).Load(context.Background())
	if err != nil {
		t.Fatalf("real policy.yaml failed to load: %v", err)
	}
	sp, ok := p.(*SimplePolicy)
	if !ok {
		t.Fatalf("policy is %T, want *SimplePolicy", p)
	}
	if sp.rule.MinSLSA != 3 {
		t.Errorf("MinSLSA = %d, want 3", sp.rule.MinSLSA)
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func TestFileLoader_InvalidMinSLSA(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.yaml")
	if err := os.WriteFile(path, []byte("min_slsa_level: 4"), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewFileLoader(path)
	_, err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("expected error for min_slsa_level > 3")
	}
}
