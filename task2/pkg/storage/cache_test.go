package storage

import (
	"context"
	"enclave-task2/pkg/keys"
	"testing"
	"time"

	"github.com/tj/assert"
)

var cache *InMemoryCache

func TestCache(t *testing.T) {
	ctx := context.Background()
	ticker = time.NewTicker(20 * time.Millisecond)
	if cache == nil {
		cache = NewInMemoryCache()
	}

	key, err := keys.New("test-key", 10*time.Minute)
	assert.NoError(t, err)

	// Test Put
	err = cache.Put(ctx, key)
	assert.NoError(t, err)

	// Test Get
	actualKey, err := cache.Get(ctx, key.Name)
	assert.NoError(t, err)

	assert.NoError(t, err)

	assert.Equal(t, key.Name, actualKey.Name)
	assert.Equal(t, key.TTL, actualKey.TTL)
	assert.Equal(t, key.CreatedAt.Unix(), actualKey.CreatedAt.Unix())

	// Test Delete
	err = cache.Delete(ctx, key.Name)
	assert.NoError(t, err)

	_, err = cache.Get(ctx, key.Name)
	assert.Error(t, err)
	assert.Equal(t, NotFoundError, err)

	// Cache miss
	_, err = cache.Get(ctx, "non-existent-key")
	assert.Error(t, err)
	assert.Equal(t, NotFoundError, err)

	// expiry
	key, err = keys.New("expiring-key", 20*time.Millisecond)
	assert.NoError(t, err)

	err = cache.Put(ctx, key)
	assert.NoError(t, err)

	time.Sleep(60 * time.Millisecond)

	_, err = cache.Get(ctx, key.Name)
	assert.Error(t, err)
	assert.Equal(t, NotFoundError, err)

	// expiry
	key, err = keys.New("expiring-key2", 120*time.Millisecond)
	assert.NoError(t, err)

	err = cache.Put(ctx, key)
	assert.NoError(t, err)

	time.Sleep(60 * time.Millisecond)

	_, err = cache.Get(ctx, key.Name)
	assert.Error(t, err)
	assert.Equal(t, NotFoundError, err)

}
