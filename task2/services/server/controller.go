package server

import (
	"enclave-task2/pkg/keys"
	"io"
	"net/http"
)

func (s *Server) CreateKyberKey(rw http.ResponseWriter, req *http.Request) {
	keyName := req.PathValue("name")
	if keyName == "" {
		http.Error(rw, "key name is required", http.StatusBadRequest)
		return
	}

	key, err := keys.New(keyName)
	if err != nil {
		http.Error(rw, "failed to create key", http.StatusInternalServerError)
		return
	}

	// s.storage.Put(keyName, key.Pack())

	rw.WriteHeader(http.StatusNoContent)
}

func (s *Server) Encrypt(rw http.ResponseWriter, req *http.Request) {
	keyName := req.PathValue("name")
	if keyName == "" {
		http.Error(rw, "key name is required", http.StatusBadRequest)
		return
	}

	// if !s.storage.Has(keyName) {
	// 	http.Error(rw, "key not found", http.StatusNotFound)
	// 	return
	// }

	// keyBytes, err := s.storage.Get(keyName)
	// if err != nil {
	// 	http.Error(rw, "failed to get key", http.StatusInternalServerError)
	// 	return
	// }

	// key, err := keys.Unpack(keyBytes)
	// if err != nil {
	// 	http.Error(rw, "failed to unpack key", http.StatusInternalServerError)
	// 	return
	// }

	// read plaintext from request body
	plaintext, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(rw, "failed to read request body", http.StatusBadRequest)
		return
	}

	ciphertext := key.Encrypt(plaintext)
	rw.WriteHeader(http.StatusOK)
	rw.Write(ciphertext)
}

func (s *Server) Decrypt(rw http.ResponseWriter, req *http.Request) {
	keyName := req.PathValue("name")
	if keyName == "" {
		http.Error(rw, "key name is required", http.StatusBadRequest)
		return
	}

	if !s.storage.Has(keyName) {
		http.Error(rw, "key not found", http.StatusNotFound)
		return
	}

	keyBytes, err := s.storage.Get(keyName)
	if err != nil {
		http.Error(rw, "failed to get key", http.StatusInternalServerError)
		return
	}

	key, err := keys.Unpack(keyBytes)
	if err != nil {
		http.Error(rw, "failed to unpack key", http.StatusInternalServerError)
		return
	}

	// read ciphertext from request body
	ciphertext, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(rw, "failed to read request body", http.StatusBadRequest)
		return
	}

	plaintext := key.Decrypt(ciphertext)
	rw.WriteHeader(http.StatusOK)
	rw.Write(plaintext)
}
