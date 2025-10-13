package server

import (
	"context"
	"enclave-task2/pkg/common"
	"enclave-task2/pkg/keys"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/mailgun/groupcache/v2"
	"golang.org/x/sync/errgroup"
)

type Storage interface {
	Put(ctx context.Context, key *keys.Key) error
	Get(ctx context.Context, key string) (*keys.Key, error)
	Delete(ctx context.Context, key string) error
}

type Server struct {
	api *http.Server
	mux *http.ServeMux
	gc  *http.Server

	storage Storage

	logger *slog.Logger
}

// NewServer creates a new Server instance.
func New(storage Storage) *Server {
	return &Server{
		api: &http.Server{
			Addr: ":8080",
		},
		mux: http.NewServeMux(),
		gc: &http.Server{
			Addr: ":8081",
		},
		storage: storage,
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

	s.api.Handler = initMiddlewares(ctx, s.mux)

	errWg, errCtx := errgroup.WithContext(ctx)

	errWg.Go(func() error {
		// Start api server
		lc := net.ListenConfig{}
		l, err := lc.Listen(ctx, "tcp", s.api.Addr)
		if err != nil {
			s.logger.Error("failed to start listener", "error", err.Error())
			return err
		}
		s.logger.Info("server started", "address", s.api.Addr)
		s.logger.Info("Use the following token to authenticate with server", "token", token)
		if s.api.TLSConfig != nil {
			return s.api.ServeTLS(l, "", "")
		}

		return s.api.Serve(l)
	})

	errWg.Go(func() error {
		// Start groupcache server
		pool := groupcache.NewHTTPPoolOpts("http://127.0.0.1:8081", &groupcache.HTTPPoolOptions{})
		s.gc.Handler = pool

		lc := net.ListenConfig{}
		l, err := lc.Listen(ctx, "tcp", s.gc.Addr)
		if err != nil {
			s.logger.Error("failed to start listener", "error", err.Error())
			return err
		}
		s.logger.Info("groupcache server started", "address", s.gc.Addr)
		if s.gc.TLSConfig != nil {
			return s.gc.ServeTLS(l, "", "")
		}

		return s.gc.Serve(l)
	})

	errWg.Go(func() error {
		<-errCtx.Done()
		timeoutCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
		defer cancel()

		s.api.Shutdown(timeoutCtx)
		s.gc.Shutdown(timeoutCtx)

		return nil
	})
	err := errWg.Wait()

	if err == context.Canceled || err == http.ErrServerClosed || err == nil {
		s.logger.Info("gracefully quit server")

		return nil
	}
	s.logger.Error("server stopped with error", "error", err.Error())

	return err
}
