package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr string

	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	HandlerTimeout    time.Duration

	// APIKey 是阶段四 /metrics 等受保护端点的预留字段，阶段一不读取。
	APIKey string

	// TLS 证书路径。
	TLSCertPath string
	TLSKeyPath  string

	// 签名验证相关。
	TrustedRootPath  string // 离线信任根 JSON 路径
	IdentityFilePath string // 身份 allowlist YAML 路径
	AllowUnsigned    bool   // 仅开发模式：跳过验签
	// AllowUnsignedAndSkipPolicy 是 AllowUnsigned 之上的第二道闸门。
	// 跳过验签后没有 VerifiedIdentity，策略无法判定，必须显式再关一次策略，
	// 否则服务要么全拒（看不出是配置问题），要么被迫写"空身份放行"的漏洞。
	AllowUnsignedAndSkipPolicy bool

	// OCI 拉取防护。
	// AllowedRegistries 是 registry host 白名单，逗号分隔。
	// 为空表示不限制——仅限开发，生产必须配置，否则任何能创建 Pod 的用户
	// 都能借准入服务向任意 host 发起出站请求（SSRF）。
	AllowedRegistries []string
	// MaxAttestationBytes 是单个 attestation layer 的读取上限，单位字节。
	MaxAttestationBytes int64
}

type timeoutField struct {
	key string
	dst *time.Duration
	def time.Duration
}

func Load() (Config, error) {
	cfg := Config{APIKey: os.Getenv("ATTEST_API_KEY")}

	if v, ok := os.LookupEnv("ATTEST_ADDR"); ok {
		if v == "" {
			return Config{}, errors.New("ATTEST_ADDR is set but empty")
		}
		cfg.Addr = v
	} else {
		cfg.Addr = ":8090"
	}

	if v, ok := os.LookupEnv("ATTEST_TLS_CERT"); ok {
		if v == "" {
			return Config{}, errors.New("ATTEST_TLS_CERT is set but empty")
		}
		cfg.TLSCertPath = v
	} else {
		cfg.TLSCertPath = "certs/tls.crt"
	}

	if v, ok := os.LookupEnv("ATTEST_TLS_KEY"); ok {
		if v == "" {
			return Config{}, errors.New("ATTEST_TLS_KEY is set but empty")
		}
		cfg.TLSKeyPath = v
	} else {
		cfg.TLSKeyPath = "certs/tls.key"
	}

	if v, ok := os.LookupEnv("ATTEST_TRUSTED_ROOT"); ok {
		if v == "" {
			return Config{}, errors.New("ATTEST_TRUSTED_ROOT is set but empty")
		}
		cfg.TrustedRootPath = v
	} else {
		cfg.TrustedRootPath = "trusted_root.json"
	}

	if v, ok := os.LookupEnv("ATTEST_IDENTITY_FILE"); ok {
		if v == "" {
			return Config{}, errors.New("ATTEST_IDENTITY_FILE is set but empty")
		}
		cfg.IdentityFilePath = v
	} else {
		cfg.IdentityFilePath = "identities.yaml"
	}

	switch os.Getenv("ATTEST_ALLOW_UNSIGNED") {
	case "", "false", "0":
		cfg.AllowUnsigned = false
	case "true", "1":
		cfg.AllowUnsigned = true
	default:
		return Config{}, fmt.Errorf("ATTEST_ALLOW_UNSIGNED must be true/false, got %q", os.Getenv("ATTEST_ALLOW_UNSIGNED"))
	}

	switch os.Getenv("ATTEST_ALLOW_UNSIGNED_AND_SKIP_POLICY") {
	case "", "false", "0":
		cfg.AllowUnsignedAndSkipPolicy = false
	case "true", "1":
		cfg.AllowUnsignedAndSkipPolicy = true
	default:
		return Config{}, fmt.Errorf("ATTEST_ALLOW_UNSIGNED_AND_SKIP_POLICY must be true/false, got %q",
			os.Getenv("ATTEST_ALLOW_UNSIGNED_AND_SKIP_POLICY"))
	}

	// 注册表白名单：逗号分隔，去除空白与空项。
	cfg.MaxAttestationBytes = 4 << 20
	if v, ok := os.LookupEnv("ATTEST_ALLOWED_REGISTRIES"); ok {
		for _, h := range strings.Split(v, ",") {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			cfg.AllowedRegistries = append(cfg.AllowedRegistries, h)
		}
	}
	if v, ok := os.LookupEnv("ATTEST_MAX_ATTESTATION_BYTES"); ok {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return Config{}, fmt.Errorf("parse ATTEST_MAX_ATTESTATION_BYTES: %w", err)
		}
		if n <= 0 {
			return Config{}, fmt.Errorf("ATTEST_MAX_ATTESTATION_BYTES must be positive, got %d", n)
		}
		cfg.MaxAttestationBytes = n
	}

	fields := []timeoutField{
		{"ATTEST_READ_TIMEOUT", &cfg.ReadTimeout, 5 * time.Second},
		{"ATTEST_READ_HEADER_TIMEOUT", &cfg.ReadHeaderTimeout, 2 * time.Second},
		{"ATTEST_WRITE_TIMEOUT", &cfg.WriteTimeout, 10 * time.Second},
		{"ATTEST_IDLE_TIMEOUT", &cfg.IdleTimeout, 120 * time.Second},
		{"ATTEST_SHUTDOWN_TIMEOUT", &cfg.ShutdownTimeout, 10 * time.Second},
		{"ATTEST_HANDLER_TIMEOUT", &cfg.HandlerTimeout, 4 * time.Second},
	}
	for _, f := range fields {
		*f.dst = f.def
		if v := os.Getenv(f.key); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf("parse %s: %w", f.key, err)
			}
			*f.dst = d
		}
	}
	for _, f := range fields {
		if *f.dst <= 0 {
			return Config{}, fmt.Errorf("%s must be positive, got %s", f.key, *f.dst)
		}
	}
	if cfg.ReadHeaderTimeout >= cfg.ReadTimeout {
		return Config{}, fmt.Errorf("ATTEST_READ_HEADER_TIMEOUT (%s) must be less than ATTEST_READ_TIMEOUT (%s)",
			cfg.ReadHeaderTimeout, cfg.ReadTimeout)
	}
	if cfg.HandlerTimeout >= cfg.WriteTimeout {
		return Config{}, fmt.Errorf("ATTEST_HANDLER_TIMEOUT (%s) must be less than ATTEST_WRITE_TIMEOUT (%s)",
			cfg.HandlerTimeout, cfg.WriteTimeout)
	}

	return cfg, nil
}
