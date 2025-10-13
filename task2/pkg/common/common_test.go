package common

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoggerFuncs(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx := context.Background()
	ctx = LoggerWithContext(ctx, logger)

	retrievedLogger := GetLoggerFromContext(ctx)
	assert.NotNil(t, retrievedLogger)
	assert.Equal(t, logger, retrievedLogger)

	emptyCtx := context.Background()
	assert.Nil(t, GetLoggerFromContext(emptyCtx))
	assert.Nil(t, GetLoggerFromContext(nil))
}
