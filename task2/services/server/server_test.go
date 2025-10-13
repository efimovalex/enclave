package server

import (
	"context"
	"enclave-task2/pkg/common"
	"enclave-task2/pkg/storage"
	"log/slog"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestServerGracefulStop(t *testing.T) {
	ctx := context.Background()
	if cache == nil {
		cache = storage.NewInMemoryCache()
	}
	logger := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx = common.LoggerWithContext(ctx, logger)

	server := New(cache)

	go func() {
		time.Sleep(25 * time.Millisecond)
		syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	}()

	err := server.Start(ctx)
	assert.NoError(t, err)
	logger.Info("Server started and stopped successfully")
}
