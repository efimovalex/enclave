package keys

import (
	"bytes"
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

	separatorByte = byte(0xFF)
)

func New(keyType, size, name string, ttl time.Duration) (Key, error) {
	switch keyType {
	case KyberKeyType:
		return NewKyberKey(name, size, ttl)
		// add other key types here
	default:
		return nil, fmt.Errorf("unknown key type: %s", keyType)
	}
}

func Unpack(data []byte) (Key, error) {
	parts := bytes.SplitN(data, []byte{separatorByte}, 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid packed key")
	}

	switch string(parts[0]) {
	case "kyber":
		var key = KyberKey{size: string(parts[1])}
		if err := key.Unpack(data); err != nil {
			return nil, err
		}
		return &key, nil
	default:
		return nil, fmt.Errorf("unknown key type: %s", string(parts[0]))
	}

}
