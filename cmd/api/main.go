package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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

	srv := &http.Server{
		Addr: cfg.Addr,
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
		if err := srv.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
