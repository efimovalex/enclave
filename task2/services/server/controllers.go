package server

import (
	"enclave-task2/pkg/keys"
	"enclave-task2/pkg/storage"
	"io"
	"net/http"
	"time"
)

func (s *Server) CreateKyberKey(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	keyName := req.PathValue("name")
	if keyName == "" {
		http.Error(rw, "key name is required", http.StatusBadRequest)
		return
	}

	ttl := keys.DefaultKeyTTL
	ttlParam := req.URL.Query().Get("ttl")
	if ttlParam != "" {
		var err error
		ttl, err = time.ParseDuration(ttlParam)
		if err != nil {
			s.logger.Error("invalid ttl", "error", err)
			http.Error(rw, "invalid ttl", http.StatusBadRequest)
			return
		}
	}

	// check if key already exists
	key, err := s.storage.Get(ctx, keyName)
	if err != nil {
		if err != storage.NotFoundError {
			s.logger.Error("failed to check key existence", "error", err)
			http.Error(rw, "failed to check key existence", http.StatusInternalServerError)
			return
		}
	} else {
		// key already exists -> extend TTL
		key.TTL = ttl
		s.storage.Put(ctx, key)

		rw.WriteHeader(http.StatusNoContent)
		return
	}

	key, err = keys.New(keyName, ttl)
	if err != nil {
		s.logger.Error("failed to create key", "error", err)
		http.Error(rw, "failed to create key", http.StatusInternalServerError)
		return
	}

	s.storage.Put(ctx, key)

	rw.WriteHeader(http.StatusNoContent)
}

func (s *Server) RevokeKyberKey(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	keyName := req.PathValue("name")
	if keyName == "" {
		http.Error(rw, "key name is required", http.StatusBadRequest)
		return
	}

	err := s.storage.Delete(ctx, keyName)
	if err != nil {
		s.logger.Error("failed to delete key", "error", err)
		http.Error(rw, "failed to delete key", http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusNoContent)
}

func (s *Server) Encrypt(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	keyName := req.PathValue("name")
	if keyName == "" {
		http.Error(rw, "key name is required", http.StatusBadRequest)
		return
	}

	key, err := s.storage.Get(ctx, keyName)
	if err != nil {
		if err == storage.NotFoundError {
			http.Error(rw, "key not found", http.StatusNotFound)
			return
		}
		s.logger.Error("failed to get key", "error", err)
		http.Error(rw, "failed to get key", http.StatusInternalServerError)
		return
	}

	// read plaintext from request body
	plaintext, err := io.ReadAll(req.Body)
	if err != nil {
		s.logger.Error("failed to read request body", "error", err)
		http.Error(rw, "failed to read request body", http.StatusBadRequest)
		return
	}

	ciphertext := key.Encrypt(plaintext)
	rw.WriteHeader(http.StatusOK)
	rw.Write(ciphertext)
}

func (s *Server) Decrypt(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	keyName := req.PathValue("name")
	if keyName == "" {
		http.Error(rw, "key name is required", http.StatusBadRequest)
		return
	}

	key, err := s.storage.Get(ctx, keyName)
	if err != nil {
		if err == storage.NotFoundError {
			http.Error(rw, "key not found", http.StatusNotFound)
			return
		}
		s.logger.Error("failed to get key", "error", err)
		http.Error(rw, "failed to get key", http.StatusInternalServerError)
		return
	}

	// read ciphertext from request body
	ciphertext, err := io.ReadAll(req.Body)
	if err != nil {
		s.logger.Error("failed to read request body", "error", err)
		http.Error(rw, "failed to read request body", http.StatusBadRequest)
		return
	}

	plaintext := key.Decrypt(ciphertext)

	rw.WriteHeader(http.StatusOK)
	rw.Header().Set("Content-Type", "application/text")
	rw.Write(plaintext)
}
