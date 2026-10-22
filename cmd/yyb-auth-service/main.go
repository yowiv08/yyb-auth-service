package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"yyb-auth-service/internal/app"
	"yyb-auth-service/internal/config"
	"yyb-auth-service/internal/logging"
)

func main() {
	cfg := config.Load()
	logger := logging.NewJSONLogger(os.Stdout, cfg.LogLevel)

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	if err := app.Run(ctx, cfg, logger); err != nil {
		logger.Error("服务停止并返回错误", "error", err)
		os.Exit(1)
	}
}
