package app

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"yyb-auth-service/internal/config"
	"yyb-auth-service/internal/credential"
	"yyb-auth-service/internal/db"
	"yyb-auth-service/internal/httpapi"
	"yyb-auth-service/internal/logging"
	"yyb-auth-service/internal/native"
	"yyb-auth-service/internal/service"
	"yyb-auth-service/internal/store"
	"yyb-auth-service/internal/yyb"
)

func Run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	logger.Info(
		"服务配置已加载",
		"listen_addr",
		cfg.ListenAddr,
		"db_path",
		cfg.DBPath,
		"cors_origins",
		cfg.CORSOrigins,
		"log_level",
		cfg.LogLevel.String(),
		"log_timezone",
		logging.TimezoneName,
	)

	handle, err := db.Open(ctx, cfg.DBPath)
	if err != nil {
		return err
	}
	defer handle.Close()

	server, err := newHTTPServer(ctx, handle, cfg, logger)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("run http server: %w", err)
	}
	defer listener.Close()

	errs := make(chan error, 1)
	go func() {
		logger.Info("HTTP服务开始监听", "addr", cfg.ListenAddr)
		errs <- server.Serve(listener)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown http server: %w", err)
		}
		return nil
	case err := <-errs:
		if err == nil || err == http.ErrServerClosed {
			return nil
		}
		return fmt.Errorf("run http server: %w", err)
	}
}

func newHTTPServer(
	ctx context.Context,
	handle *sql.DB,
	cfg config.Config,
	logger *slog.Logger,
) (*http.Server, error) {
	accountStore := store.NewAccountStore(handle)
	scanStore := store.NewScanStore(handle)
	settingStore := store.NewSettingStore(handle)

	bearerToken, err := settingStore.EnsureBearerToken(ctx)
	if err != nil {
		return nil, err
	}
	logger.Info("鉴权令牌已加载", "token", bearerToken)

	yybClient := yyb.NewClient()
	credentialManager := credential.NewManager(accountStore, yybClient)
	nativeEngine := native.NewEngine(yybClient, credentialManager)

	accountService := service.NewAccountService(accountStore, credentialManager)
	exchangeService := service.NewExchangeService(
		accountStore,
		nativeEngine,
		credentialManager,
		logger,
	)
	cloudService := service.NewCloudService(
		accountStore,
		nativeEngine,
		credentialManager,
		logger,
	)
	userInfoService := service.NewUserInfoService(credentialManager, yybClient)
	oauthService := service.NewOAuthService(
		accountStore,
		nativeEngine,
		credentialManager,
		logger,
	)
	scanService := service.NewScanService(
		scanStore,
		accountService,
		yybClient,
		logger,
	)

	handler := httpapi.NewServer(
		accountService,
		exchangeService,
		cloudService,
		scanService,
		userInfoService,
		oauthService,
		logger,
		bearerToken,
	).Handler()
	handler = httpapi.CORSHandler(cfg.CORSOrigins, handler)
	return &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}, nil
}
