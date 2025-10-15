package server

import (
	"bytes"
	"context"
	"enclave-task2/pkg/keys"
	"enclave-task2/pkg/keys/kyber"
	"enclave-task2/pkg/storage"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var cache *storage.InMemoryCache

func TestCreateKyberKey(t *testing.T) {
	ctx := context.Background()
	if cache == nil {
		cache = storage.NewInMemoryCache()
	}

	server := New(cache)
	server.logger = slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("key name missing", func(t *testing.T) {

		req := httptest.NewRequest(http.MethodPost, "/transit/keys/test-key", nil)
		req = req.WithContext(ctx)
		rw := httptest.NewRecorder()

		server.CreateKyberKey(rw, req)

		assert.Equal(t, http.StatusBadRequest, rw.Result().StatusCode)
		assert.Equal(t, "key name is required\n", rw.Body.String())
	})

	t.Run("succeess", func(t *testing.T) {

		req := httptest.NewRequest(http.MethodPost, "/transit/keys/test-key", nil)
		req = req.WithContext(ctx)
		req.SetPathValue("name", "test-key")
		rw := httptest.NewRecorder()

		server.CreateKyberKey(rw, req)
		t.Log(rw.Body.String())
		assert.Equal(t, http.StatusNoContent, rw.Result().StatusCode)

		// Verify key is stored
		_, err := cache.Get(ctx, "test-key")
		assert.NoError(t, err)
	})

	t.Run("conflict -> extends ttl", func(t *testing.T) {

		req := httptest.NewRequest(http.MethodPost, "/transit/keys/test-key", nil)
		req = req.WithContext(ctx)
		req.SetPathValue("name", "test-key")
		rw := httptest.NewRecorder()

		req.Header.Set("X-Key-TTL", "55m")

		server.CreateKyberKey(rw, req)

		t.Log(rw.Body.String())
		assert.Equal(t, http.StatusNoContent, rw.Result().StatusCode)

		// Verify key is stored
		k, err := cache.Get(ctx, "test-key")
		assert.NoError(t, err)
		assert.Equal(t, 55*time.Minute, k.GetTTL())
	})

	t.Run("invalid ttl", func(t *testing.T) {

		req := httptest.NewRequest(http.MethodPost, "/transit/keys/test-key", nil)
		req = req.WithContext(ctx)
		req.SetPathValue("name", "test-key2")

		req.Header.Set("X-Key-TTL", "invalid-ttl")
		rw := httptest.NewRecorder()

		server.CreateKyberKey(rw, req)

		assert.Equal(t, http.StatusBadRequest, rw.Result().StatusCode)

		// Verify key is stored
		_, err := cache.Get(ctx, "test-key2")
		assert.Equal(t, storage.NotFoundError, err)
	})
	t.Run("ttl", func(t *testing.T) {

		req := httptest.NewRequest(http.MethodPost, "/transit/keys/test-key", nil)
		req = req.WithContext(ctx)
		req.SetPathValue("name", "test-key2")
		req.Header.Set("X-Key-TTL", "5m")
		rw := httptest.NewRecorder()

		server.CreateKyberKey(rw, req)

		assert.Equal(t, http.StatusNoContent, rw.Result().StatusCode)

		// Verify key is stored
		k, err := cache.Get(ctx, "test-key2")
		assert.NoError(t, err)
		assert.Equal(t, 5*time.Minute, k.GetTTL())
	})

}

func TestRevokeKyberKey(t *testing.T) {
	ctx := context.Background()
	if cache == nil {
		cache = storage.NewInMemoryCache()
	}
	server := New(cache)
	server.logger = slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))

	key, err := keys.New(ctx, kyber.KeyType, kyber.Size1024, "test-key", keys.DefaultKeyTTL)
	assert.NoError(t, err)
	// Create key
	err = cache.Put(ctx, key)
	assert.NoError(t, err)

	t.Run("key name missing", func(t *testing.T) {

		req := httptest.NewRequest(http.MethodDelete, "/transit/keys/test-key", nil)
		req = req.WithContext(ctx)
		rw := httptest.NewRecorder()

		server.RevokeKyberKey(rw, req)

		assert.Equal(t, http.StatusBadRequest, rw.Result().StatusCode)
		assert.Equal(t, "key name is required\n", rw.Body.String())
	})

	t.Run("success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/transit/keys/test-key", nil)
		req = req.WithContext(ctx)
		req.SetPathValue("name", "test-key")
		rw := httptest.NewRecorder()

		server.RevokeKyberKey(rw, req)

		assert.Equal(t, http.StatusNoContent, rw.Result().StatusCode)

		// Verify key is deleted
		_, err := cache.Get(ctx, "test-key")
		assert.Equal(t, storage.NotFoundError, err)
	})

	t.Run("idempotent not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/transit/keys/non-existing-key", nil)
		req = req.WithContext(ctx)
		req.SetPathValue("name", "non-existing-key")
		rw := httptest.NewRecorder()

		server.RevokeKyberKey(rw, req)

		assert.Equal(t, http.StatusNoContent, rw.Result().StatusCode)

		// Verify key is deleted
		_, err := cache.Get(ctx, "test-key")
		assert.Equal(t, storage.NotFoundError, err)
	})
}

func TestEncrypt(t *testing.T) {
	ctx := context.Background()
	if cache == nil {
		cache = storage.NewInMemoryCache()
	}

	server := New(cache)
	server.logger = slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))

	key, err := keys.New(ctx, kyber.KeyType, kyber.Size1024, "test-key", keys.DefaultKeyTTL)
	assert.NoError(t, err)
	// Create key
	err = cache.Put(ctx, key)
	assert.NoError(t, err)

	t.Run("key name missing", func(t *testing.T) {

		req := httptest.NewRequest(http.MethodPost, "/transit/encrypt/test-key", nil)
		req = req.WithContext(ctx)
		rw := httptest.NewRecorder()

		server.Encrypt(rw, req)

		assert.Equal(t, http.StatusBadRequest, rw.Result().StatusCode)
		assert.Equal(t, "key name is required\n", rw.Body.String())
	})

	t.Run("key not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/transit/encrypt/non-existing-key", nil)
		req = req.WithContext(ctx)
		req.SetPathValue("name", "non-existing-key")
		rw := httptest.NewRecorder()

		server.Encrypt(rw, req)

		assert.Equal(t, http.StatusNotFound, rw.Result().StatusCode)
		assert.Equal(t, "key not found\n", rw.Body.String())
	})

	t.Run("empty body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/transit/encrypt/test-key", nil)
		req = req.WithContext(ctx)
		req.SetPathValue("name", "test-key")
		rw := httptest.NewRecorder()

		server.Encrypt(rw, req)

		assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
		assert.Equal(t, "", rw.Body.String())
	})

	t.Run("success", func(t *testing.T) {
		plaintext := "Hello, World!"
		req := httptest.NewRequest(http.MethodPost, "/transit/encrypt/test-key", nil)
		req = req.WithContext(ctx)
		req.SetPathValue("name", "test-key")
		req.Body = io.NopCloser(strings.NewReader(plaintext))
		rw := httptest.NewRecorder()

		server.Encrypt(rw, req)

		assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
		ciphertext := rw.Body.String()
		assert.NotEmpty(t, ciphertext)
		assert.NotEqual(t, plaintext, ciphertext)
	})
}

func TestDecrypt(t *testing.T) {
	ctx := context.Background()
	if cache == nil {
		cache = storage.NewInMemoryCache()
	}

	server := New(cache)
	server.logger = slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))

	key, err := keys.New(ctx, kyber.KeyType, kyber.Size1024, "test-key", keys.DefaultKeyTTL)
	assert.NoError(t, err)
	// Create key
	err = cache.Put(ctx, key)
	assert.NoError(t, err)

	plaintext := "Hello, World!"
	ciphertext := key.Encrypt([]byte(plaintext))

	t.Run("key name missing", func(t *testing.T) {

		req := httptest.NewRequest(http.MethodPost, "/transit/decrypt/test-key", nil)
		req = req.WithContext(ctx)
		rw := httptest.NewRecorder()

		server.Decrypt(rw, req)

		assert.Equal(t, http.StatusBadRequest, rw.Result().StatusCode)
		assert.Equal(t, "key name is required\n", rw.Body.String())
	})

	t.Run("key not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/transit/decrypt/non-existing-key", nil)
		req = req.WithContext(ctx)
		req.SetPathValue("name", "non-existing-key")
		rw := httptest.NewRecorder()

		server.Decrypt(rw, req)

		assert.Equal(t, http.StatusNotFound, rw.Result().StatusCode)
		assert.Equal(t, "key not found\n", rw.Body.String())
	})

	t.Run("empty body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/transit/decrypt/test-key", nil)
		req = req.WithContext(ctx)
		req.SetPathValue("name", "test-key")
		rw := httptest.NewRecorder()

		server.Decrypt(rw, req)

		assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
		assert.Equal(t, "", rw.Body.String())
	})

	t.Run("success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/transit/decrypt/test-key", nil)
		req = req.WithContext(ctx)
		req.SetPathValue("name", "test-key")
		req.Body = io.NopCloser(bytes.NewReader(ciphertext))
		rw := httptest.NewRecorder()

		server.Decrypt(rw, req)

		assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
		decryptedText := rw.Body.String()
		assert.Equal(t, plaintext, decryptedText)
	})
}

func TestEncryptDecryptLargeData(t *testing.T) {
	ctx := context.Background()
	if cache == nil {
		cache = storage.NewInMemoryCache()
	}

	server := New(cache)
	server.logger = slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))

	key, err := keys.New(ctx, kyber.KeyType, kyber.Size1024, "test-key", keys.DefaultKeyTTL)
	assert.NoError(t, err)
	// Create key
	err = cache.Put(ctx, key)
	assert.NoError(t, err)

	// Generate large plaintext > 1024 bytes
	var sb strings.Builder
	for i := 0; i < 200; i++ {
		sb.WriteString("The quick brown fox jumps over the lazy dog. ")
	}
	plaintext := sb.String()
	assert.Greater(t, len(plaintext), 1024)

	// Encrypt
	req := httptest.NewRequest(http.MethodPost, "/transit/encrypt/test-key", nil)
	req = req.WithContext(ctx)
	req.SetPathValue("name", "test-key")
	req.Body = io.NopCloser(strings.NewReader(plaintext))
	rw := httptest.NewRecorder()

	server.Encrypt(rw, req)

	assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
	ciphertext := rw.Body.String()
	assert.NotEmpty(t, ciphertext)
	assert.NotEqual(t, plaintext, ciphertext)

	// Decrypt
	req = httptest.NewRequest(http.MethodPost, "/transit/decrypt/test-key", nil)
	req = req.WithContext(ctx)
	req.SetPathValue("name", "test-key")
	req.Body = io.NopCloser(strings.NewReader(ciphertext))
	rw = httptest.NewRecorder()

	server.Decrypt(rw, req)

	assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
	decryptedText := rw.Body.String()
	assert.Equal(t, plaintext, decryptedText)

	t.Log(decryptedText)
}
