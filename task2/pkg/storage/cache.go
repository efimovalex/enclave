package storage

import (
	"context"
	"enclave-task2/pkg/keys"
	"errors"
	"log"
	"time"

	"github.com/mailgun/groupcache/v2"
)

var (
	NotFoundError = errors.New("key not found")
	ticker        = time.NewTicker(1 * time.Minute)
)

type Cache interface {
	Put(key string, value []byte) error
	Get(key string) ([]byte, error)
	Has(key string) bool
}

type InMemoryCache struct {
	gc *groupcache.Group

	keys map[string]keys.Key
}

func NewInMemoryCache() *InMemoryCache {
	mc := InMemoryCache{
		keys: make(map[string]keys.Key),
	}

	gc := groupcache.NewGroup("keys", 64<<20, groupcache.GetterFunc(
		func(ctx context.Context, key string, dest groupcache.Sink) error {
			log.Println("looking up", key)
			v, ok := mc.keys[key]
			if !ok {
				return errors.New("key not found")
			}
			dest.SetBytes(v.Pack(), time.Now().Add(v.GetTTL()))
			return nil
		},
	))
	mc.gc = gc

	go mc.CheckTTL()

	return &mc
}

func (mc *InMemoryCache) CheckTTL() {
	go func() {
		for range ticker.C {
			now := time.Now()
			for k, v := range mc.keys {
				if v.GetTTL() > 0 && now.Sub(v.GetCreatedAt()) > v.GetTTL() {
					mc.gc.Remove(context.Background(), k)
				}
			}
		}
	}()
}

func (mc *InMemoryCache) Put(ctx context.Context, key keys.Key) error {
	mc.gc.Set(ctx, key.GetName(), key.Pack(), key.GetCreatedAt().Add(key.GetTTL()), true)
	return nil
}

func (mc *InMemoryCache) Get(ctx context.Context, keyName string) (keys.Key, error) {
	var data []byte
	err := mc.gc.Get(ctx, keyName, groupcache.AllocatingByteSliceSink(&data))
	if err != nil {
		if err.Error() == "key not found" {
			return nil, NotFoundError
		}
		return nil, err
	}

	key, err := keys.Unpack(data)
	if err != nil {
		return nil, err
	}

	// check if key is expired
	if key.GetTTL() > 0 && time.Since(key.GetCreatedAt()) > key.GetTTL() {
		mc.gc.Remove(ctx, keyName)
		return nil, NotFoundError
	}

	return key, nil
}

func (mc *InMemoryCache) Delete(ctx context.Context, key string) error {
	if err := mc.gc.Remove(ctx, key); err != nil {
		return err
	}

	return nil
}
