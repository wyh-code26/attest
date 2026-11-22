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
