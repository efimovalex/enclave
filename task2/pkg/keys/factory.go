package keys

import (
	"bytes"
	"context"
	"enclave-task2/pkg/common"
	"enclave-task2/pkg/keys/kyber"
	"enclave-task2/pkg/keys/rsa"
	"fmt"
	"time"
)

type Key interface {
	Pack() []byte
	Unpack(data []byte) error

	Encrypt(plaintext []byte) []byte
	Decrypt(ciphertext []byte) []byte

	SetTTL(ttl time.Duration)

	GetName() string
	GetType() string
	GetSize() string
	GetCreatedAt() time.Time
	GetTTL() time.Duration
}

const (
	// KeyTTL defines how long a key is valid.
	DefaultKeyTTL = 25 * time.Minute
)

func New(ctx context.Context, keyType, size, name string, ttl time.Duration) (Key, error) {
	switch keyType {
	case kyber.KeyType:
		return kyber.NewKyberKey(ctx, name, size, ttl)
	case rsa.KeyType:
		return rsa.NewRsaKey(ctx, name, size, ttl)

	default:
		return nil, fmt.Errorf("unknown key type: %s", keyType)
	}
}

func Unpack(data []byte) (Key, error) {
	parts := bytes.SplitN(data, []byte{common.SeparatorByte}, 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid packed key")
	}

	switch string(parts[0]) {
	case "kyber":
		var key kyber.KyberKey
		key.SetSize(string(parts[1]))
		if err := key.Unpack(data); err != nil {
			return nil, err
		}
		return &key, nil
	case rsa.KeyType:
		var key rsa.RsaKey
		key.SetSize(string(parts[1]))
		if err := key.Unpack(data); err != nil {
			return nil, err
		}
		return &key, nil
	default:
		return nil, fmt.Errorf("unknown key type: %s", string(parts[0]))
	}

}
