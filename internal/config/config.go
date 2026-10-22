package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	ListenAddr  string
	DBPath      string
	LogLevel    slog.Level
	CORSOrigins []string
}

func Load() Config {
	runtimeDir := firstNonEmpty(
		os.Getenv("YYB_RUNTIME_DIR"),
		filepath.Join(defaultBaseDir(), "runtime"),
	)

	return Config{
		ListenAddr: firstNonEmpty(os.Getenv("YYB_LISTEN_ADDR"), "127.0.0.1:8080"),
		DBPath: firstNonEmpty(
			os.Getenv("YYB_DB_PATH"),
			filepath.Join(runtimeDir, "yyb.db"),
		),
		LogLevel:    parseLogLevel(os.Getenv("YYB_LOG_LEVEL")),
		CORSOrigins: splitCSV(firstNonEmpty(os.Getenv("YYB_CORS_ORIGINS"), "*")),
	}
}

func defaultBaseDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return cwd
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func parseLogLevel(raw string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
