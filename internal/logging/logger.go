package logging

import (
	"context"
	"io"
	"log/slog"
	"time"
)

const TimezoneName = "Asia/Shanghai"
const localTimeLayout = "2006-01-02T15:04:05.999999999"

func NewJSONLogger(out io.Writer, level slog.Leveler) *slog.Logger {
	return slog.New(
		slog.NewJSONHandler(
			out,
			&slog.HandlerOptions{
				Level:       level,
				ReplaceAttr: replaceAttr,
			},
		),
	)
}

func replaceAttr(_ []string, attr slog.Attr) slog.Attr {
	switch attr.Key {
	case slog.TimeKey:
		if value, ok := attr.Value.Any().(time.Time); ok {
			attr.Value = slog.StringValue(value.In(ShanghaiLocation()).Format(localTimeLayout))
		}
	case slog.LevelKey:
		attr.Value = slog.StringValue(attr.Value.String())
	case slog.MessageKey:
		attr.Key = "msg"
	}
	return attr
}

func ShanghaiLocation() *time.Location {
	location, err := time.LoadLocation(TimezoneName)
	if err != nil {
		return time.FixedZone("CST", 8*60*60)
	}
	return location
}

func WithAttrs(
	ctx context.Context,
	logger *slog.Logger,
	msg string,
	attrs ...slog.Attr,
) {
	if logger == nil {
		return
	}
	logger.LogAttrs(ctx, slog.LevelInfo, msg, attrs...)
}
