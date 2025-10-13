package server

import (
	"context"
	"enclave-task2/pkg/common"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitMiddlewares(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx := context.Background()
	ctx = common.LoggerWithContext(ctx, logger)

	mux := http.NewServeMux()

	mux.Handle("/test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := common.GetLoggerFromContext(r.Context())

		assert.NotNil(t, logger)

		// Simulate some processing
		logger.Info("Processing request")
		// Respond with a simple message
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	mw := initMiddlewares(ctx, mux)
	assert.NotNil(t, mw)

	req, err := http.NewRequest("GET", "/test", nil)
	assert.NoError(t, err)

	// Test without Authorization header
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Result().StatusCode)

	req.Header.Set("Authorization", "Bearer invalidtoken")
	rr = httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Result().StatusCode)

	req.Header.Set("Authorization", "Bearer "+token)
	rr = httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Result().StatusCode)
	assert.Equal(t, "ok", rr.Body.String())
}
