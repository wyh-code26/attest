package config

import (
	"os"
	"testing"
	"time"
)

var (
	addrKey      = "ATTEST_ADDR"
	apiKey       = "ATTEST_API_KEY"
	tlsCertKey   = "ATTEST_TLS_CERT"
	tlsKeyKey    = "ATTEST_TLS_KEY"
	trustedRoot  = "ATTEST_TRUSTED_ROOT"
	identityFile = "ATTEST_IDENTITY_FILE"
	allowUnsign  = "ATTEST_ALLOW_UNSIGNED"
	timeoutKeys  = []string{
		"ATTEST_READ_TIMEOUT",
		"ATTEST_READ_HEADER_TIMEOUT",
		"ATTEST_WRITE_TIMEOUT",
		"ATTEST_IDLE_TIMEOUT",
		"ATTEST_SHUTDOWN_TIMEOUT",
		"ATTEST_HANDLER_TIMEOUT",
	}
)

func clearEnv(t *testing.T) {
	t.Helper()
	keys := append(
		[]string{addrKey, apiKey, tlsCertKey, tlsKeyKey, trustedRoot, identityFile, allowUnsign},
		timeoutKeys...,
	)
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
	strings := map[string]struct{ got, want string }{
		"Addr":             {cfg.Addr, ":8090"},
		"TLSCertPath":      {cfg.TLSCertPath, "certs/tls.crt"},
		"TLSKeyPath":       {cfg.TLSKeyPath, "certs/tls.key"},
		"TrustedRootPath":  {cfg.TrustedRootPath, "sigstore_trusted_root.json"},
		"IdentityFilePath": {cfg.IdentityFilePath, "identities.yaml"},
	}
	for name, c := range strings {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", name, c.got, c.want)
		}
	}
	durations := map[string]struct{ got, want time.Duration }{
		"ReadTimeout":       {cfg.ReadTimeout, 5 * time.Second},
		"ReadHeaderTimeout": {cfg.ReadHeaderTimeout, 2 * time.Second},
		"WriteTimeout":      {cfg.WriteTimeout, 10 * time.Second},
		"IdleTimeout":       {cfg.IdleTimeout, 120 * time.Second},
		"ShutdownTimeout":   {cfg.ShutdownTimeout, 10 * time.Second},
		"HandlerTimeout":    {cfg.HandlerTimeout, 4 * time.Second},
	}
	for name, d := range durations {
		if d.got != d.want {
			t.Errorf("%s = %v, want %v", name, d.got, d.want)
		}
	}
	if cfg.AllowUnsigned {
		t.Error("AllowUnsigned = true, want false")
	}
}

func TestLoad_Overrides(t *testing.T) {
	clearEnv(t)
	t.Setenv(addrKey, ":9999")
	t.Setenv(tlsCertKey, "/custom/cert.pem")
	t.Setenv(tlsKeyKey, "/custom/key.pem")
	t.Setenv(trustedRoot, "/custom/trusted_root.json")
	t.Setenv(identityFile, "/custom/identities.yaml")
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
	if cfg.TLSCertPath != "/custom/cert.pem" {
		t.Errorf("TLSCertPath = %q", cfg.TLSCertPath)
	}
	if cfg.TLSKeyPath != "/custom/key.pem" {
		t.Errorf("TLSKeyPath = %q", cfg.TLSKeyPath)
	}
	if cfg.TrustedRootPath != "/custom/trusted_root.json" {
		t.Errorf("TrustedRootPath = %q", cfg.TrustedRootPath)
	}
	if cfg.IdentityFilePath != "/custom/identities.yaml" {
		t.Errorf("IdentityFilePath = %q", cfg.IdentityFilePath)
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

func TestLoad_AllowUnsignedParsing(t *testing.T) {
	tests := []struct {
		val  string
		want bool
		ok   bool
	}{
		{"", false, true},
		{"false", false, true},
		{"0", false, true},
		{"true", true, true},
		{"1", true, true},
		{"yes", false, false},
		{"TRUE", false, false},
	}
	for _, tt := range tests {
		t.Run("val="+tt.val, func(t *testing.T) {
			clearEnv(t)
			if tt.val != "" {
				t.Setenv(allowUnsign, tt.val)
			}
			cfg, err := Load()
			if tt.ok {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if cfg.AllowUnsigned != tt.want {
					t.Errorf("AllowUnsigned = %v, want %v", cfg.AllowUnsigned, tt.want)
				}
			} else if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// TestLoad_EmptyEnvVars 覆盖所有"显式设为空"的报错路径。
func TestLoad_EmptyEnvVars(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{"empty addr", addrKey},
		{"empty tls cert", tlsCertKey},
		{"empty tls key", tlsKeyKey},
		{"empty trusted root", trustedRoot},
		{"empty identity file", identityFile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)
			t.Setenv(tt.key, "")
			if _, err := Load(); err == nil {
				t.Fatalf("expected error for empty %s", tt.key)
			}
		})
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
