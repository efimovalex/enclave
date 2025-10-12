package server

import (
	"context"
	"enclave-task2/pkg/common"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
)

type Storage interface {
	Put(key string, value []byte) error
	Get(key string) ([]byte, error)
	Delete(key string) error
	Has(key string) bool
}

type Server struct {
	*http.Server

	mux *http.ServeMux

	logger *slog.Logger
}

// NewServer creates a new Server instance.
func New(storage Storage) *Server {
	return &Server{
		Server: &http.Server{
			Addr: ":8080",
		},
		mux: http.NewServeMux(),
	}
}

// Start starts the server.
func (s *Server) Start(ctx context.Context) error {
	s.logger = common.GetLoggerFromContext(ctx)

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL)
	defer stop()

	s.mux.Handle("POST /transit/keys/{name}", http.HandlerFunc(s.CreateKyberKey))
	s.mux.Handle("DELETE /transit/keys/{name}", http.HandlerFunc(s.RevokeKyberKey))

	s.mux.Handle("POST /transit/encrypt/{name}", http.HandlerFunc(s.Encrypt))
	s.mux.Handle("POST /transit/decrypt/{name}", http.HandlerFunc(s.Decrypt))

	s.Server.Handler = initMiddlewares(ctx, s.mux)

	errWg, errCtx := errgroup.WithContext(ctx)

	errWg.Go(func() error {
		lc := net.ListenConfig{}
		l, err := lc.Listen(ctx, "tcp", s.Addr)
		if err != nil {
			s.logger.Error("failed to start listener", "error", err.Error())
			return err
		}
		s.logger.Info("server started", "address", s.Addr)
		s.logger.Info("Use the following token to authenticate with server", "token", token)
		if s.TLSConfig != nil {
			return s.ServeTLS(l, "", "")
		}

		return s.Serve(l)
	})

	errWg.Go(func() error {
		<-errCtx.Done()
		timeoutCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
		defer cancel()

		return s.Shutdown(timeoutCtx)
	})
	err := errWg.Wait()

	if err == context.Canceled || err == http.ErrServerClosed || err == nil {
		s.logger.Info("gracefully quit server")

		return nil
	}
	s.logger.Error("server stopped with error", "error", err.Error())

	return err
}
