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
min_slsa: 2
allowed_builders:
  - "builder-a"
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
	if !ok || sp.rule.MinSLSA != 2 {
		t.Errorf("loaded rule unexpected: %+v", sp)
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

func TestFileLoader_InvalidMinSLSA(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "policy.yaml")
	if err := os.WriteFile(path, []byte("min_slsa: 4"), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewFileLoader(path)
	_, err := loader.Load(context.Background())
	if err == nil {
		t.Fatal("expected error for min_slsa > 3")
	}
}
