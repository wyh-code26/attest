package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/wyh-code26/attest/internal/attest"
	"github.com/wyh-code26/attest/internal/audit"
	"github.com/wyh-code26/attest/internal/config"
	"github.com/wyh-code26/attest/internal/httpapi"
	"github.com/wyh-code26/attest/internal/metrics"
	"github.com/wyh-code26/attest/internal/policy"
	"github.com/wyh-code26/attest/internal/verify"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	readiness := &httpapi.Readiness{}
	readiness.MarkReady()

	policyPath := os.Getenv("ATTEST_POLICY_PATH")
	if policyPath == "" {
		policyPath = "policy.yaml"
	}
	pol, err := policy.NewFileLoader(policyPath).Load(context.Background())
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	// 签名验证：按配置构造 Verifier。
	// AllowUnsigned=true 仅用于本地开发，生产环境必须注入 verifier。
	var verifier verify.Verifier
	if cfg.AllowUnsigned {
		logger.Warn("ATTEST_ALLOW_UNSIGNED=true: signature verification is DISABLED. Do not use in production.")
		// 未验签时拿不到 VerifiedIdentity，策略层无法做任何有意义的判定。
		// 直接拒绝启动比“跑起来但全部 deny”或“跑起来且全部 allow”都安全：
		// 前者会让人误以为服务坏了，后者是零安全。
		// 确实需要跳过策略时，请额外设置 ATTEST_ALLOW_UNSIGNED_AND_SKIP_POLICY=true。
		if !cfg.AllowUnsignedAndSkipPolicy {
			return fmt.Errorf("ATTEST_ALLOW_UNSIGNED=true but ATTEST_ALLOW_UNSIGNED_AND_SKIP_POLICY=false: " +
				"policy evaluation requires a verified identity; set ATTEST_ALLOW_UNSIGNED_AND_SKIP_POLICY=true for local dev")
		}
		logger.Warn("ATTEST_ALLOW_UNSIGNED_AND_SKIP_POLICY=true: policy evaluation is DISABLED. Do not use in production.")
		verifier = nil
		// 未验签就没有 VerifiedIdentity，任何真实策略都会全拒。
		// 用 AllowAll 显式替代，让"策略被关掉"这件事在代码里可见，
		// 而不是靠 SimplePolicy 默默放行空身份。
		pol = &policy.AllowAll{}
	} else {
		trust, err := verify.NewFileTrustMaterial(cfg.TrustedRootPath)
		if err != nil {
			return fmt.Errorf("load trusted root: %w", err)
		}
		rules, err := verify.LoadIdentitiesFromFile(cfg.IdentityFilePath)
		if err != nil {
			return fmt.Errorf("load identities: %w", err)
		}
		verifier, err = verify.NewSigstoreVerifier(trust, rules)
		if err != nil {
			return fmt.Errorf("build sigstore verifier: %w", err)
		}
		logger.Info("signature verification enabled",
			"trusted_root", cfg.TrustedRootPath,
			"identities_file", cfg.IdentityFilePath,
			"rule_count", len(rules),
		)
	}

	opts := []attest.Option{}
	if verifier != nil {
		opts = append(opts, attest.WithVerifier(verifier))
	}
	// OCI 拉取防护：registry 白名单 + 读取上限 + 带超时的 transport。
	// 不配白名单仍能跑，但会打警告——因为它意味着准入服务可以代他人访问任意 host。
	if len(cfg.AllowedRegistries) > 0 {
		opts = append(opts, attest.WithAllowedRegistries(cfg.AllowedRegistries...))
		logger.Info("registry allowlist enabled", "registries", cfg.AllowedRegistries)
	} else {
		logger.Warn("ATTEST_ALLOWED_REGISTRIES is empty: admission service will dial any registry host referenced by a Pod. Set it in production.")
	}
	opts = append(opts,
		attest.WithMaxAttestationBytes(cfg.MaxAttestationBytes),
		attest.WithTransport(&http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          32,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 3 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}),
	)
	ociFetcher := attest.NewOCIFetcher(opts...)

	m := metrics.New()
	auditRec := audit.NewRecorder(os.Stdout)

	// 证书热加载。
	//
	// ListenAndServeTLS 只在启动时读一次证书文件。在 cert-manager 管理证书的
	// 部署形态下，这是真实故障点：证书续期会更新 Secret，kubelet 随后把新文件
	// 写进挂载的 /app/certs，但进程仍用着启动时那份旧证书。等到旧证书过期，
	// apiserver 就连不上 webhook，failurePolicy: Fail 下整个集群无法创建 Pod——
	// 而证书看起来是好的，排障极难定位。
	//
	// 这里改为每次 TLS 握手按需重读文件：续期后无需重启 Pod 即可生效。
	// 重读失败时回退到上一份可用证书，避免证书文件短暂不一致（cert-manager
	// 写 Secret 与 kubelet 同步挂载点之间有窗口）导致握手全挂。
	certReloader := newCertReloader(logger, cfg.TLSCertPath, cfg.TLSKeyPath)

	srv := &http.Server{
		Addr: cfg.Addr,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certReloader.GetCertificate,
		},
		Handler: httpapi.NewRouter(httpapi.RouterDeps{
			Logger:    logger,
			Readiness: readiness,
			AdmissionHandler: httpapi.AdmissionHandler(httpapi.AdmissionDeps{
				Logger:  logger,
				Fetcher: ociFetcher,
				Policy:  pol,
				Metrics: m,
				Audit:   auditRec,
			}),
			MetricsHandler: m.Handler(),
			HandlerTimeout: cfg.HandlerTimeout,
		}),
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("server listening (TLS)", "addr", cfg.Addr, "policy", policyPath)
		// 传空文件名：证书由上面的 TLSConfig.GetCertificate 提供。
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	logger.Info("server stopped gracefully")
	return nil
}

// certReloader 按需重读 TLS 证书，使证书续期无需重启进程即可生效。
//
// 设计取舍：
//   - 不用 fsnotify 监听文件变化：容器里 /app/certs 是 Secret 挂载，
//     kubelet 更新走的是符号链接原子替换（..data -> ..data_tmp），
//     监听具体文件会因 inode 变化而失效。
//   - 改为每次握手 stat 文件并与上次的修改时间/大小比对，只在变化时重读。
//     stat 的开销远小于一次 TLS 握手本身，可忽略。
//   - 重读失败保留上一份证书：宁可继续用旧证书（在有效期内仍可用），
//     也不要让所有握手瞬间失败。
type certReloader struct {
	logger   *slog.Logger
	certPath string
	keyPath  string

	mu       sync.Mutex
	cert     *tls.Certificate
	modTime  time.Time
	size     int64
	loadErr  error
	lastWarn time.Time
}

func newCertReloader(logger *slog.Logger, certPath, keyPath string) *certReloader {
	r := &certReloader{logger: logger, certPath: certPath, keyPath: keyPath}
	// 启动时就加载一次，让证书缺失/损坏在启动阶段直接暴露，
	// 而不是等到第一个请求进来才失败。
	if _, err := r.reload(true); err != nil {
		logger.Error("failed to load TLS certificate at startup", "err", err,
			"cert", certPath, "key", keyPath)
	}
	return r
}

// GetCertificate 满足 tls.Config.GetCertificate 签名。
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.reload(false)
}

func (r *certReloader) reload(force bool) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !force && r.cert != nil {
		// 用证书文件本身判断是否变化：cert-manager 续期一定会重写 tls.crt。
		fi, err := os.Stat(r.certPath)
		if err == nil && fi.ModTime().Equal(r.modTime) && fi.Size() == r.size {
			return r.cert, nil
		}
	}

	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		r.loadErr = err
		if r.cert != nil {
			// 保留旧证书，限流告警，避免每 10 秒刷一条日志。
			if time.Since(r.lastWarn) > time.Minute {
				r.logger.Warn("failed to reload TLS certificate, keeping previous one",
					"err", err, "cert", r.certPath)
				r.lastWarn = time.Now()
			}
			return r.cert, nil
		}
		return nil, err
	}

	fi, statErr := os.Stat(r.certPath)
	if statErr == nil {
		r.modTime = fi.ModTime()
		r.size = fi.Size()
	}
	r.cert = &cert
	r.loadErr = nil
	if !force {
		r.logger.Info("TLS certificate reloaded", "cert", r.certPath)
	}
	return r.cert, nil
}
