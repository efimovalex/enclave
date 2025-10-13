package main

import (
	"context"
	"log/slog"
	"os"

	"enclave-task2/pkg/common"
	"enclave-task2/pkg/storage"
	"enclave-task2/services/server"
)

func main() {
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx = common.LoggerWithContext(ctx, logger)

	if err := run(ctx); err != nil {
		logger.Error("Application error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	logger := common.GetLoggerFromContext(ctx)

	logger.Info("Application started")

	storage := storage.NewInMemoryCache()

	// start services
	err := server.New(storage).Start(ctx)
	if err != nil {
		return err
	}

	logger.Info("Application stopped")
	return nil
}
