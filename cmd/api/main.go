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

	m := metrics.New()
	auditRec := audit.NewRecorder(os.Stdout)
	ociFetcher := attest.NewOCIFetcher()

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
