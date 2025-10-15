package rsa_test

import (
	"context"
	"enclave-task2/pkg/common"
	"enclave-task2/pkg/keys"
	"enclave-task2/pkg/keys/rsa"
	"log/slog"
	"testing"
	"time"

	"github.com/tj/assert"
)

func TestErrors(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx = context.WithValue(ctx, "logger", logger)
	_, err := rsa.NewRsaKey(ctx, "invalid-size-key", "invalid-size", keys.DefaultKeyTTL)
	assert.Error(t, err)

	var invalidData = []byte("invalid-packed-key")
	_, err = keys.Unpack(invalidData)
	assert.Error(t, err)

	invalidData = []byte("unknown-type\xff1024\xffkey-name\xff2023-10-10T10:00:00Z")
	_, err = keys.Unpack(invalidData)
	assert.Error(t, err)
}

func TestKeys(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx = common.LoggerWithContext(ctx, logger)
	testCases := []struct {
		name string
		size string
	}{
		{"test-key-2048", "2048"},
		{"test-key-4096", "4096"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := rsa.NewRsaKey(ctx, tc.name, tc.size, keys.DefaultKeyTTL+time.Minute*10)
			assert.NoError(t, err)
			assert.Equal(t, keys.DefaultKeyTTL+time.Minute*10, key.GetTTL())
			key.SetTTL(keys.DefaultKeyTTL)
			assert.Equal(t, keys.DefaultKeyTTL, key.GetTTL())

			assert.False(t, key.GetCreatedAt().IsZero())
			assert.NoError(t, err)
			assert.NotNil(t, key)

			packed := key.Pack()
			assert.NotEmpty(t, packed)

			plaintext := []byte("Hello, World!")
			ciphertext := key.Encrypt(plaintext)
			assert.NotEmpty(t, ciphertext)

			decrypted := key.Decrypt(ciphertext)
			assert.Equal(t, plaintext, decrypted)

			plaintext = []byte{}
			decrypted = key.Decrypt([]byte("a"))
			assert.Equal(t, plaintext, []byte{})

			plaintext = []byte("Short")
			ciphertext = key.Encrypt(plaintext)
			assert.NotEmpty(t, ciphertext)

			decrypted = key.Decrypt(ciphertext)
			assert.Equal(t, plaintext, decrypted)

			plaintext = []byte(`Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse viverra, leo et ullamcorper suscipit, velit ex pretium risus, ut convallis justo enim vel odio. Proin erat orci, euismod sed ultrices a, ullamcorper vitae sem. Etiam risus nisl, tempor non convallis quis, convallis at purus. Nulla euismod nisl nec vehicula consectetur. Aliquam ultricies dolor nec urna lobortis, vitae tincidunt odio rhoncus. Vestibulum ipsum augue, euismod et consequat ut, accumsan ut dui. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Nulla vitae sem lorem. Vestibulum quis mauris a lacus rhoncus gravida. Mauris fermentum rhoncus dolor et congue. Donec nec commodo dui.
	Cras sit amet molestie sem. Suspendisse interdum urna eu ipsum vestibulum tincidunt. Phasellus pretium pretium quam, at volutpat nisi bibendum nec. Nulla mattis ornare metus, vitae ultricies orci volutpat quis. Fusce ut tortor odio. In hac habitasse platea dictumst. Curabitur sit amet quam non odio gravida iaculis hendrerit rhoncus est. Sed ut consectetur odio, pellentesque dictum diam. Phasellus molestie lorem at convallis volutpat. Aenean dapibus pretium convallis. Etiam eget lacus leo. Nam volutpat erat quam, ut malesuada augue aliquam posuere. Nullam pharetra arcu non tincidunt auctor. Mauris varius augue a quam aliquam, at venenatis enim gravida. Nunc tincidunt lacus eget laoreet pulvinar. Aliquam posuere massa a orci sodales, eget dictum quam commodo.`)
			ciphertext = key.Encrypt(plaintext)
			assert.NotEmpty(t, ciphertext)

			decrypted = key.Decrypt(ciphertext)
			assert.Equal(t, plaintext, decrypted)

			var unpackedKey rsa.RsaKey
			err = unpackedKey.Unpack(packed)
			assert.NoError(t, err)
			assert.NotNil(t, unpackedKey)

			plaintext = []byte("Hello, World!")
			ciphertext = unpackedKey.Encrypt(plaintext)
			assert.NotEmpty(t, ciphertext)

			decrypted = unpackedKey.Decrypt(ciphertext)
			assert.Equal(t, plaintext, decrypted)
		})
	}
}
