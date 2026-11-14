package config

import (
	"os"
	"testing"
	"time"
)

var (
	addrKey    = "ATTEST_ADDR"
	apiKey     = "ATTEST_API_KEY"
	tlsCertKey = "ATTEST_TLS_CERT"
	tlsKeyKey  = "ATTEST_TLS_KEY"
	// 独立列出时长字段，避免用 envKeys[2:] 这类依赖数组顺序的切片——
	// 中间插一个 key 就静默错位，变成"漏测某个字段"且无人察觉。
	timeoutKeys = []string{
		"ATTEST_READ_TIMEOUT",
		"ATTEST_READ_HEADER_TIMEOUT",
		"ATTEST_WRITE_TIMEOUT",
		"ATTEST_IDLE_TIMEOUT",
		"ATTEST_SHUTDOWN_TIMEOUT",
		"ATTEST_HANDLER_TIMEOUT",
	}
)

// clearEnv 真正 unset 相关环境变量，测试结束后恢复原值。
func clearEnv(t *testing.T) {
	t.Helper()
	keys := append([]string{addrKey, apiKey, tlsCertKey, tlsKeyKey}, timeoutKeys...)
	for _, k := range keys {
		old, existed := os.LookupEnv(k)
		os.Unsetenv(k)
		k := k
		t.Cleanup(func() {
			if existed {
				os.Setenv(k, old)
			} else {
				os.Unsetenv(k)
			}
		})
	}
}

func TestLoad_Defaults(t *testing.T) {
	clearEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := map[string]struct{ got, exp time.Duration }{
		"ReadTimeout":       {cfg.ReadTimeout, 5 * time.Second},
		"ReadHeaderTimeout": {cfg.ReadHeaderTimeout, 2 * time.Second},
		"WriteTimeout":      {cfg.WriteTimeout, 10 * time.Second},
		"IdleTimeout":       {cfg.IdleTimeout, 120 * time.Second},
		"ShutdownTimeout":   {cfg.ShutdownTimeout, 10 * time.Second},
		"HandlerTimeout":    {cfg.HandlerTimeout, 4 * time.Second},
	}
	for name, w := range want {
		if w.got != w.exp {
			t.Errorf("%s = %v, want %v", name, w.got, w.exp)
		}
	}
	if cfg.Addr != ":8090" {
		t.Errorf("Addr = %q, want :8090", cfg.Addr)
	}
	if cfg.TLSCertPath != "certs/tls.crt" {
		t.Errorf("TLSCertPath = %q, want certs/tls.crt", cfg.TLSCertPath)
	}
	if cfg.TLSKeyPath != "certs/tls.key" {
		t.Errorf("TLSKeyPath = %q, want certs/tls.key", cfg.TLSKeyPath)
	}
}

func TestLoad_Overrides(t *testing.T) {
	clearEnv(t)
	t.Setenv(addrKey, ":9999")
	t.Setenv(tlsCertKey, "/tmp/cert")
	t.Setenv(tlsKeyKey, "/tmp/key")
	t.Setenv("ATTEST_READ_TIMEOUT", "3s")
	t.Setenv("ATTEST_READ_HEADER_TIMEOUT", "1s")
	t.Setenv("ATTEST_HANDLER_TIMEOUT", "2s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Addr != ":9999" {
		t.Errorf("Addr = %q", cfg.Addr)
	}
	if cfg.TLSCertPath != "/tmp/cert" {
		t.Errorf("TLSCertPath = %q", cfg.TLSCertPath)
	}
	if cfg.TLSKeyPath != "/tmp/key" {
		t.Errorf("TLSKeyPath = %q", cfg.TLSKeyPath)
	}
	if cfg.ReadTimeout != 3*time.Second {
		t.Errorf("ReadTimeout = %v", cfg.ReadTimeout)
	}
	if cfg.ReadHeaderTimeout != 1*time.Second {
		t.Errorf("ReadHeaderTimeout = %v", cfg.ReadHeaderTimeout)
	}
	if cfg.HandlerTimeout != 2*time.Second {
		t.Errorf("HandlerTimeout = %v", cfg.HandlerTimeout)
	}
}

func TestLoad_AddrSetButEmpty(t *testing.T) {
	clearEnv(t)
	t.Setenv(addrKey, "")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for empty ATTEST_ADDR")
	}
}

func TestLoad_TLSPathsSetButEmpty(t *testing.T) {
	clearEnv(t)
	t.Setenv(tlsCertKey, "")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for empty ATTEST_TLS_CERT")
	}

	t.Setenv(tlsCertKey, "valid/path")
	t.Setenv(tlsKeyKey, "")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for empty ATTEST_TLS_KEY")
	}
}

func TestLoad_Errors(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T)
	}{
		{"header >= read", func(t *testing.T) {
			t.Setenv("ATTEST_READ_TIMEOUT", "3s")
			t.Setenv("ATTEST_READ_HEADER_TIMEOUT", "3s")
		}},
		{"handler >= write", func(t *testing.T) {
			t.Setenv("ATTEST_WRITE_TIMEOUT", "5s")
			t.Setenv("ATTEST_HANDLER_TIMEOUT", "5s")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)
			tt.setup(t)
			if _, err := Load(); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestLoad_EachTimeoutFieldRejectsInvalid 遍历每个时长字段。
// 三种失败路径：解析失败、零值、负值。
// 新增字段只要进 timeoutKeys 就自动获得覆盖，A8 的洞在这里被堵住。
func TestLoad_EachTimeoutFieldRejectsInvalid(t *testing.T) {
	for _, key := range timeoutKeys {
		key := key
		for _, v := range []string{"abc", "0", "-1s"} {
			v := v
			t.Run(key+"/"+v, func(t *testing.T) {
				clearEnv(t)
				t.Setenv(key, v)
				if _, err := Load(); err == nil {
					t.Errorf("%s=%q 应报错，实际通过", key, v)
				}
			})
		}
	}
}
