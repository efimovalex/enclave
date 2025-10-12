package cache

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCacheFetch(t *testing.T) {
	// TODO: simulate an HTTP server and test caching behavior

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Server reponse!"))
	}))
	defer ts.Close()

	cache := NewCache(15 * time.Second)
	data, err := cache.Fetch(context.Background(), ts.URL)

	assert.NoError(t, err)
	assert.Equal(t, []byte("Server reponse!"), data)

	// Fetch again to test cache hit
	data, err = cache.Fetch(context.Background(), ts.URL)

	assert.NoError(t, err)
	assert.Equal(t, []byte("Server reponse!"), data)

	hits, misses, size := cache.Stats()
	assert.Equal(t, 1, hits)
	assert.Equal(t, 1, misses)
	assert.Equal(t, 1, size)
}

func TestCacheConcurrency(t *testing.T) {
	// TODO: simulate concurrent fetches for the same URL
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { callCount++ }()
		// Simulate occasional failure (first call fails)
		if callCount == 0 {
			http.Error(w, "Simulated error", http.StatusInternalServerError)
			return
		}

		time.Sleep(25 * time.Millisecond) // Simulate some delay
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Concurrent Hello!"))

	}))
	defer ts.Close()

	cache := NewCache(15 * time.Second)

	var wg sync.WaitGroup
	numRequests := 10

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			data, err := cache.Fetch(context.Background(), ts.URL)
			assert.Equal(t, []byte("Concurrent Hello!"), data, "Goroutine %d", idx)
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()

	hits, misses, size := cache.Stats()
	assert.Equal(t, 0, hits)
	assert.Equal(t, 10, misses)
	assert.Equal(t, 1, size)

}

func TestCacheTTL(t *testing.T) {
	// TODO: test TTL expiration and re-fetch

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Server reponse!"))
	}))
	defer ts.Close()

	cache := NewCache(5 * time.Second)
	data, err := cache.Fetch(context.Background(), ts.URL, 5*time.Millisecond)

	assert.NoError(t, err)
	assert.Equal(t, []byte("Server reponse!"), data)

	time.Sleep(6 * time.Millisecond) // Wait for TTL to expire
	// Fetch again to test cache hit
	data, err = cache.Fetch(context.Background(), ts.URL)

	assert.NoError(t, err)
	assert.Equal(t, []byte("Server reponse!"), data)

	hits, misses, size := cache.Stats()
	assert.Equal(t, 0, hits)
	assert.Equal(t, 1, misses)
	assert.Equal(t, 1, size)
}
