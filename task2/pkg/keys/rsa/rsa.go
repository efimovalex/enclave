package rsa

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"enclave-task2/pkg/common"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"strconv"
	"time"
)

const (
	KeyType   = "rsa"
	dataParts = 8 // number of parts in packed key data
)

type RsaKey struct {
	Name       string
	keyType    string
	size       string
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey

	CreatedAt time.Time
	TTL       time.Duration

	logger *slog.Logger
}

func NewRsaKey(ctx context.Context, name, size string, ttl time.Duration) (*RsaKey, error) {
	intSize, err := strconv.Atoi(size)
	if err != nil {
		return nil, fmt.Errorf("invalid key size: %w", err)
	}

	if intSize < 2048 || intSize > 4096 {
		return nil, fmt.Errorf("unsupported key size: %d", intSize)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, intSize)
	if err != nil {
		return nil, err
	}
	publicKey := privateKey.PublicKey

	privateKey.Precompute()
	if err := privateKey.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate generated key: %w", err)
	}

	return &RsaKey{
		Name:       name,
		keyType:    "rsa",
		size:       size,
		publicKey:  &publicKey,
		privateKey: privateKey,
		CreatedAt:  time.Now(),
		TTL:        ttl,
		logger:     common.GetLoggerFromContext(ctx),
	}, nil
}

func (k *RsaKey) GetName() string {
	return k.Name
}

func (k *RsaKey) GetCreatedAt() time.Time {
	return k.CreatedAt
}

func (k *RsaKey) GetTTL() time.Duration {
	return k.TTL
}
func (k *RsaKey) SetTTL(ttl time.Duration) {
	k.TTL = ttl
}

func (k *RsaKey) GetType() string {
	return k.keyType
}

func (k *RsaKey) GetSize() string {
	return k.size
}
func (k *RsaKey) SetSize(size string) {
	k.size = size
}

func (k *RsaKey) Encrypt(plaintext []byte) []byte {
	var ciphertext []byte
	seed := sha512.New()
	ciphertext, err := EncryptOAEP(seed, rand.Reader, k.publicKey, plaintext, nil)
	if err != nil {
		k.logger.Error("failed to encrypt data", "error", err)
	}

	return ciphertext
}

func (k *RsaKey) Decrypt(ciphertext []byte) []byte {
	var plaintext = []byte{}
	seed := sha512.New()
	plaintext, err := DecryptOAEP(seed, rand.Reader, k.privateKey, ciphertext, nil)
	if err != nil {
		k.logger.Error("failed to decrypt data", "error", err)
	}

	return plaintext
}

func (k *RsaKey) Pack() []byte {

	// pack name, seed, public and private keys into a single byte slice
	packed := bytes.NewBuffer([]byte{})

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(k.publicKey),
	})

	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k.privateKey),
	})
	if pubBytes == nil || privBytes == nil {
		k.logger.Error("failed to encode keys")
		return nil
	}

	fmt.Println("Pack", "pubKeyBytes", string(pubBytes), "privKeyBytes", string(privBytes))
	packed.WriteString(k.keyType)
	packed.WriteByte(common.SeparatorByte)
	packed.WriteString(k.size)
	packed.WriteByte(common.SeparatorByte)
	packed.WriteString(k.Name)
	packed.WriteByte(common.SeparatorByte)
	packed.Write([]byte(k.CreatedAt.Format(time.RFC3339)))
	packed.WriteByte(common.SeparatorByte)
	packed.Write([]byte(k.TTL.String()))
	packed.WriteByte(common.SeparatorByte)
	packed.Write([]byte(fmt.Sprint(len(pubBytes))))
	packed.WriteByte(common.SeparatorByte)
	packed.Write([]byte(fmt.Sprint(len(privBytes))))
	packed.WriteByte(common.SeparatorByte)
	packed.Write(pubBytes)
	packed.Write(privBytes)

	return packed.Bytes()
}

func (k *RsaKey) Unpack(data []byte) error {
	if k == nil {
		k = &RsaKey{}
	}

	var err error
	parts := bytes.SplitN(data, []byte{common.SeparatorByte}, dataParts)
	if len(parts) != dataParts {
		return fmt.Errorf("invalid packed key")
	}

	k.keyType = string(parts[dataParts-8])
	k.size = string(parts[dataParts-7])
	k.Name = string(parts[dataParts-6])

	k.CreatedAt, err = time.Parse(time.RFC3339, string(parts[dataParts-5]))
	if err != nil {
		return fmt.Errorf("invalid created at time: %w", err)
	}

	k.TTL, err = time.ParseDuration(string(parts[dataParts-4]))
	if err != nil {
		return fmt.Errorf("invalid ttl: %w", err)
	}

	publicKeySize, err := strconv.Atoi(string(parts[dataParts-3]))
	if err != nil {
		return fmt.Errorf("invalid public key size: %w", err)
	}

	privateKeySize, err := strconv.Atoi(string(parts[dataParts-2]))
	if err != nil {
		return fmt.Errorf("invalid private key size: %w", err)
	}

	rest := parts[dataParts-1]

	if len(rest) < int(publicKeySize+privateKeySize) {
		return fmt.Errorf("invalid packed key size")
	}
	k.privateKey = &rsa.PrivateKey{}
	k.publicKey = &rsa.PublicKey{}

	pubKeyBytes := rest[:publicKeySize+publicKeySize]
	privKeyBytes := rest[publicKeySize:]

	fmt.Println("Unpack", "pubKeyBytes", string(pubKeyBytes), "privKeyBytes", string(privKeyBytes))

	block, _ := pem.Decode(pubKeyBytes)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return fmt.Errorf("failed to decode public key")
	}

	k.publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	block, _ = pem.Decode(privKeyBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("failed to decode private key")
	}

	k.privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	return nil
}

func EncryptOAEP(hash hash.Hash, random io.Reader, public *rsa.PublicKey, msg []byte, label []byte) ([]byte, error) {
	msgLen := len(msg)
	step := public.Size() - 2*hash.Size() - 2
	var encryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		encryptedBlockBytes, err := rsa.EncryptOAEP(hash, random, public, msg[start:finish], label)
		if err != nil {
			return nil, err
		}

		encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
	}

	return encryptedBytes, nil
}

func DecryptOAEP(hash hash.Hash, random io.Reader, private *rsa.PrivateKey, msg []byte, label []byte) ([]byte, error) {
	msgLen := len(msg)
	step := private.PublicKey.Size()
	var decryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		decryptedBlockBytes, err := rsa.DecryptOAEP(hash, random, private, msg[start:finish], label)
		if err != nil {
			return nil, err
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}

	return decryptedBytes, nil
}
