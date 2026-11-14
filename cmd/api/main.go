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

	"github.com/wyh-code26/attest/internal/config"
	"github.com/wyh-code26/attest/internal/httpapi"
)

// main 只负责构造顶层依赖并调用 run。
// 用 os.Exit(1) 而非 panic：启动错误已由 logger 记录，退出码是对外契约。
func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// 设置包级默认 logger，让标准库和未来可能引入的第三方库
	// 的日志也走 JSON 格式。这只发生在 main 包，不影响 httpapi
	// 的"无全局可变状态"约定——httpapi 不读 slog.Default()。
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

	// 阶段一没有需要初始化的外部依赖，直接标记就绪。
	// 阶段三接入策略加载后，改为加载成功后再 MarkReady。
	readiness.MarkReady()

	// Fail Fast：启动前检查 TLS 文件是否存在，避免隐藏在底层的 TLS 握手错误。
	// 生产环境默认路径通常由 K8s Secret 挂载到 /etc/tls/，需通过环境变量覆盖。
	if _, err := os.Stat(cfg.TLSCertPath); err != nil {
		return fmt.Errorf("TLS cert not found at %s: %w", cfg.TLSCertPath, err)
	}
	if _, err := os.Stat(cfg.TLSKeyPath); err != nil {
		return fmt.Errorf("TLS key not found at %s: %w", cfg.TLSKeyPath, err)
	}

	srv := &http.Server{
		Addr: cfg.Addr,
		Handler: httpapi.NewRouter(httpapi.RouterDeps{
			Logger:           logger,
			Readiness:        readiness,
			AdmissionHandler: httpapi.AdmissionHandler(logger),
			HandlerTimeout:   cfg.HandlerTimeout,
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
		// 改用 ListenAndServeTLS
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
