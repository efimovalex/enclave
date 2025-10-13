package server

import (
	"context"
	"net/http"
	"strings"
)

var token = "I6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30" // Should be replaced with a secure token management system

func initMiddlewares(ctx context.Context, next http.Handler) http.Handler {
	return authMiddleware(
		insertContextMiddleware(ctx, next),
	)
}

func insertContextMiddleware(ctx context.Context, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		req = req.WithContext(ctx)

		next.ServeHTTP(rw, req)
	})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {

		authHeader := req.Header["Authorization"]
		if len(authHeader) == 0 || !strings.HasPrefix(authHeader[0], "Bearer ") {
			http.Error(rw, "missing or invalid authorization header", http.StatusUnauthorized)
			return
		}

		jwtToken := strings.TrimPrefix(authHeader[0], "Bearer ")
		if jwtToken != token {
			http.Error(rw, "invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(rw, req)
	})
}
