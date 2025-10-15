package keys

import (
	"testing"

	"github.com/tj/assert"
)

func TestFactory(t *testing.T) {

	// Test kyber key creation
	key, err := New("kyber", "1024", "test-kyber-key", DefaultKeyTTL)
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, "kyber", key.GetType())
	assert.Equal(t, "1024", key.GetSize())
	assert.Equal(t, "test-kyber-key", key.GetName())

	// Test unknown key type
	key, err = New("unknown", "1024", "test-unknown-key", DefaultKeyTTL)
	assert.Error(t, err)
	assert.Nil(t, key)

	// Test unpacking a valid kyber key
	kyberKey, err := New("kyber", "1024", "unpack-kyber-key", DefaultKeyTTL)
	assert.NoError(t, err)
	packed := kyberKey.Pack()

	unpackedKey, err := Unpack(packed)
	assert.NoError(t, err)
	assert.NotNil(t, unpackedKey)
	assert.Equal(t, kyberKey.GetName(), unpackedKey.GetName())
	assert.Equal(t, kyberKey.GetType(), unpackedKey.GetType())
	assert.Equal(t, kyberKey.GetSize(), unpackedKey.GetSize())
}
