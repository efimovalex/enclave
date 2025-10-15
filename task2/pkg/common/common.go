package common

import (
	"context"
	"log/slog"
)

const (
	LoggerContextKey = "logger"
	SeparatorByte    = byte(0xFF)
)

func GetLoggerFromContext(ctx context.Context) *slog.Logger {
	if ctx == nil {
		return nil
	}
	val := ctx.Value(LoggerContextKey)
	if val == nil {
		return nil
	}

	logger, ok := val.(*slog.Logger)
	if !ok {
		return nil
	}
	return logger
}

func LoggerWithContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, LoggerContextKey, logger)
}
