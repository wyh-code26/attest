package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/wyh-code26/attest/internal/attest"
	"github.com/wyh-code26/attest/internal/config"
	"github.com/wyh-code26/attest/internal/httpapi"
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

	// 阶段二早期：用 FakeFetcher + AllowAll 先把链路跑通。
	// 阶段二后期替换为真实的 OCI Fetcher 和声明式 Policy。
	fakeFetcher := attest.NewFakeFetcher(map[string]*attest.Provenance{
		// 这条记录用来在联调时验证 allow 路径。
		"sha256:1111111111111111111111111111111111111111111111111111111111111111": {
			BuildType: "https://slsa.dev/provenance/v1",
			Builder:   "https://github.com/actions/runner",
			SourceURI: "https://github.com/wyh-code26/attest",
		},
	})

	srv := &http.Server{
		Addr: cfg.Addr,
		Handler: httpapi.NewRouter(httpapi.RouterDeps{
			Logger:    logger,
			Readiness: readiness,
			AdmissionHandler: httpapi.AdmissionHandler(httpapi.AdmissionDeps{
				Logger:  logger,
				Fetcher: fakeFetcher,
				Policy:  &policy.AllowAll{},
			}),
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
		logger.Info("server listening (TLS)", "addr", cfg.Addr)
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
