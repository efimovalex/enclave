package cache

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

var defaultTransport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	IdleConnTimeout: 30 * time.Second,
	MaxIdleConns:    100,
}

type Cache struct {
	// Default TTL for cache entries
	defaultTTL time.Duration

	// HTTP client for fetching
	httpClient http.Client

	// Cache storage
	storage map[string]cacheEntry
	mu      sync.RWMutex

	// in-flight requests to deduplicate
	inFlight map[string][]chan []byte
	inMu     sync.Mutex

	//Stats
	hits   atomic.Uint64
	misses atomic.Uint64
}

// cacheEntry represents a cached HTTP response body
type cacheEntry struct {
	data      []byte
	timestamp time.Time
	ttl       time.Duration
}

// NewCache creates a new Cache with the specified default TTL for entries.
func NewCache(defaultTTL time.Duration) *Cache {
	return &Cache{
		defaultTTL: defaultTTL,
		httpClient: http.Client{
			Timeout:   10 * time.Second,
			Transport: defaultTransport,
		},
		storage:  make(map[string]cacheEntry),
		inFlight: make(map[string][]chan []byte),
	}
}

// Fetch retrieves the content from the given URL, using the cache if possible.
// If ttlOverride is provided, it overrides the default TTL for this fetch.
func (c *Cache) Fetch(ctx context.Context, url string, ttlOverride ...time.Duration) ([]byte, error) {
	c.mu.RLock()
	if entry, ok := c.storage[url]; ok {
		if time.Since(entry.timestamp) < entry.ttl {
			c.hits.Add(1)
			return entry.data, nil
		}
		// Expired, remove
		c.mu.RUnlock()
		c.mu.Lock()
		delete(c.storage, url)
		c.mu.Unlock()
	} else {
		c.mu.RUnlock()
		c.misses.Add(1)
	}

	data, err := c.fetchWithDeduplication(ctx, url, 3)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.storage[url] = cacheEntry{
		data:      data,
		timestamp: time.Now(),
		ttl:       append(ttlOverride, c.defaultTTL)[0],
	}
	c.mu.Unlock()

	return data, nil
}

// fetchWithDeduplication ensures that only one fetch is in-flight for a given URL.
// Other requests for the same URL will wait for the result of the in-flight request.
func (c *Cache) fetchWithDeduplication(ctx context.Context, url string, retries int) ([]byte, error) {
	c.inMu.Lock()
	if dedup, loaded := c.inFlight[url]; loaded {
		// joint the in-flight request listeners
		ch := make(chan []byte, 1)
		c.inFlight[url] = append(dedup, ch)
		c.inMu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case data := <-ch:
			if data == nil {
				// fetch failed
				if retries > 0 {
					return c.fetchWithDeduplication(ctx, url, retries-1)
				}
			}
			return data, nil
		}
	} else {
		c.inFlight[url] = make([]chan []byte, 0)
		c.inMu.Unlock()

		data, err := c.fetch(ctx, url)

		c.inMu.Lock()
		for _, waiter := range c.inFlight[url] {
			waiter <- data // nil in case of error
		}
		delete(c.inFlight, url)
		c.inMu.Unlock()

		fmt.Println("Fetched", url, "with data length", len(data), "error", err)

		if err != nil && retries > 0 {
			return c.fetchWithDeduplication(ctx, url, retries-1)
		}

		return data, err
	}
}

// fetch executes the actual HTTP GET request.
func (c *Cache) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Non-200 response: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// Stats returns the current cache statistics
func (c *Cache) Stats() (hits int, misses int, entries int) {
	return int(c.hits.Load()), int(c.misses.Load()), len(c.storage)
}
