package config

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// Config 存放应用启动所需的全部配置。
type Config struct {
	Addr string // HTTP 监听地址，如 ":8090"

	ReadTimeout       time.Duration // 读取整个请求（含 body）的超时
	ReadHeaderTimeout time.Duration // 仅读请求头；必须严格小于 ReadTimeout，否则 Slowloris 防护失效
	WriteTimeout      time.Duration // 写响应；必须大于 ValidatingWebhookConfiguration 的 timeoutSeconds（当前 5s）
	IdleTimeout       time.Duration // keep-alive 空闲连接
	ShutdownTimeout   time.Duration // 优雅关闭最长等待
	HandlerTimeout    time.Duration // handler 内部逻辑；必须严格小于 timeoutSeconds，确保 apiserver 断开前主动放弃

	// APIKey 是阶段四 /metrics 等受保护端点的预留字段，阶段一不读取。
	// /admission 由 kube-apiserver 调用，认证依赖 TLS 而非共享密钥（立项书 7.3）。
	APIKey string

	// TLSCertPath 和 TLSKeyPath 是服务端证书和私钥的路径。
	TLSCertPath string
	TLSKeyPath  string
}

// timeoutField 把「环境变量名 + 目标指针 + 默认值」绑在一起。
// 加载、校验共用同一份定义：新增字段只改一处，不会出现"加了字段但漏了校验"的静默缺口。
type timeoutField struct {
	key string
	dst *time.Duration
	def time.Duration
}

// Load 从环境变量读配置，应用默认值并校验。
// 返回错误表示配置非法，调用方应直接退出进程。
func Load() (Config, error) {
	cfg := Config{APIKey: os.Getenv("ATTEST_API_KEY")}

	// 监听地址：区分「未设置」与「设为空」。
	// 显式设为空是错误配置，报错而非静默纠正——fail closed 的项目不该猜用户意图。
	if v, ok := os.LookupEnv("ATTEST_ADDR"); ok {
		if v == "" {
			return Config{}, errors.New("ATTEST_ADDR is set but empty")
		}
		cfg.Addr = v
	} else {
		cfg.Addr = ":8090"
	}

	// TLS 证书路径读取：同样区分「未设置」与「设为空」。
	if v, ok := os.LookupEnv("ATTEST_TLS_CERT"); ok {
		if v == "" {
			return Config{}, errors.New("ATTEST_TLS_CERT is set but empty")
		}
		cfg.TLSCertPath = v
	} else {
		cfg.TLSCertPath = "certs/tls.crt" // 默认本地开发路径
	}

	if v, ok := os.LookupEnv("ATTEST_TLS_KEY"); ok {
		if v == "" {
			return Config{}, errors.New("ATTEST_TLS_KEY is set but empty")
		}
		cfg.TLSKeyPath = v
	} else {
		cfg.TLSKeyPath = "certs/tls.key" // 默认本地开发路径
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

	// 所有超时必须是正数。0 在 http.Server 中表示「无限制」，
	// 对 failurePolicy: Fail 的 webhook 等于拆掉防御。
	for _, f := range fields {
		if *f.dst <= 0 {
			return Config{}, fmt.Errorf("%s must be positive, got %s", f.key, *f.dst)
		}
	}

	// 层次约束。跨字段关系不校验就等于没约束：
	// 任何一项被单独调坏，防护会在不报错的情况下失效。
	if cfg.ReadHeaderTimeout >= cfg.ReadTimeout {
		return Config{}, fmt.Errorf(
			"ATTEST_READ_HEADER_TIMEOUT (%s) must be less than ATTEST_READ_TIMEOUT (%s)",
			cfg.ReadHeaderTimeout, cfg.ReadTimeout)
	}
	if cfg.HandlerTimeout >= cfg.WriteTimeout {
		return Config{}, fmt.Errorf(
			"ATTEST_HANDLER_TIMEOUT (%s) must be less than ATTEST_WRITE_TIMEOUT (%s)",
			cfg.HandlerTimeout, cfg.WriteTimeout)
	}

	return cfg, nil
}
