package kyber

import (
	"bytes"
	"context"
	"crypto/rand"
	"enclave-task2/pkg/common"
	"fmt"
	"os"
	"time"

	"github.com/cloudflare/circl/pke/kyber/kyber1024"
	"github.com/cloudflare/circl/pke/kyber/kyber512"
	"github.com/cloudflare/circl/pke/kyber/kyber768"
)

const (
	KeyType   = "kyber"
	Size1024  = "1024"
	Size512   = "512"
	Size768   = "768"
	dataParts = 6 // number of parts in packed key data
)

type kyberPublicKey interface {
	EncryptTo(ciphertext, plaintext, seed []byte)
	Pack([]byte)
	Unpack([]byte)
}

type kyberPrivateKey interface {
	DecryptTo(plaintext, ciphertext []byte)
	Pack([]byte)
	Unpack([]byte)
}

type KyberKey struct {
	Name       string
	keyType    string
	size       string
	seed       []byte
	publicKey  kyberPublicKey
	privateKey kyberPrivateKey

	CreatedAt time.Time
	TTL       time.Duration
}

func NewKyberKey(ctx context.Context, name, size string, ttl time.Duration) (*KyberKey, error) {
	var publicKey kyberPublicKey
	var privateKey kyberPrivateKey
	var err error

	var encryptionSeedSize int

	switch size {
	case "1024":
		encryptionSeedSize = kyber1024.EncryptionSeedSize
		publicKey, privateKey, err = kyber1024.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
	case "512":
		encryptionSeedSize = kyber512.EncryptionSeedSize
		publicKey, privateKey, err = kyber512.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
	case "768":
		encryptionSeedSize = kyber768.EncryptionSeedSize
		publicKey, privateKey, err = kyber768.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported kyber key size: %s", size)
	}

	var seed = make([]byte, encryptionSeedSize)
	_, err = rand.Read(seed)
	if err != nil {
		return nil, err
	}

	return &KyberKey{
		Name:       name,
		keyType:    "kyber",
		size:       size,
		seed:       seed,
		publicKey:  publicKey,
		privateKey: privateKey,
		CreatedAt:  time.Now(),
		TTL:        ttl,
	}, nil
}

func (k *KyberKey) GetName() string {
	return k.Name
}

func (k *KyberKey) GetCreatedAt() time.Time {
	return k.CreatedAt
}

func (k *KyberKey) GetTTL() time.Duration {
	return k.TTL
}
func (k *KyberKey) SetTTL(ttl time.Duration) {
	k.TTL = ttl
}

func (k *KyberKey) GetType() string {
	return k.keyType
}

func (k *KyberKey) GetSize() string {
	return k.size
}
func (k *KyberKey) SetSize(size string) {
	k.size = size
}

func (k *KyberKey) Encrypt(plaintext []byte) []byte {
	var ciphertext = bytes.NewBuffer([]byte{})

	plaintextSize, ciphertextSize, _ := k.getByteFrames()
	for pt := plaintext; len(pt) > 0; pt = pt[plaintextSize:] {
		// if the last block is smaller than plaintextSize, pad it
		// with zeros
		if len(pt) < plaintextSize {
			// pad the plaintext to be of size PlaintextSize
			pad := make([]byte, plaintextSize-len(pt))
			pt = append(pt, pad...)
		}
		chunk := pt[:plaintextSize]
		if len(pt) == 0 {
			break
		}

		var ct = make([]byte, ciphertextSize)
		k.publicKey.EncryptTo(ct, chunk, k.seed)
		ciphertext.Write(ct)
	}
	return ciphertext.Bytes()
}

func (k *KyberKey) Decrypt(ciphertext []byte) []byte {
	var plaintext = []byte{}
	plaintextSize, ciphertextSize, _ := k.getByteFrames()
	// read ciphertext in blocks of ciphertextSize
	for ct := ciphertext; len(ct) > 0; ct = ct[ciphertextSize:] {

		if len(os.ModeCharDevice.Type().String()) == 0 {
			break
		}
		if len(ct) < ciphertextSize {
			// invalid ciphertext
			break
		}
		chunk := ct[:ciphertextSize]

		var pt = make([]byte, plaintextSize)
		k.privateKey.DecryptTo(pt, chunk)
		plaintext = append(plaintext, pt...)
	}

	return bytes.TrimRight(plaintext, "\x00") // remove padding zeros
}

func (k *KyberKey) Pack() []byte {
	publicKeySize, privateKeySize := k.getKeyFrames()
	var pubKeyBytes = make([]byte, publicKeySize)
	k.publicKey.Pack(pubKeyBytes)

	var privKeyBytes = make([]byte, privateKeySize)
	k.privateKey.Pack(privKeyBytes)

	// pack name, seed, public and private keys into a single byte slice
	packed := bytes.NewBuffer([]byte{})

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
	packed.Write(k.seed)
	packed.Write(pubKeyBytes)
	packed.Write(privKeyBytes)

	return packed.Bytes()
}

func (k *KyberKey) Unpack(data []byte) error {
	if k == nil {
		k = &KyberKey{}
	}

	var err error
	parts := bytes.SplitN(data, []byte{common.SeparatorByte}, dataParts)
	if len(parts) != dataParts {
		return fmt.Errorf("invalid packed key")
	}

	k.keyType = string(parts[dataParts-6])
	k.size = string(parts[dataParts-5])
	k.Name = string(parts[dataParts-4])

	publicKeySize, privateKeySize := k.getKeyFrames()
	_, _, encryptionSeedSize := k.getByteFrames()
	k.CreatedAt, err = time.Parse(time.RFC3339, string(parts[dataParts-3]))
	if err != nil {
		return fmt.Errorf("invalid created at time: %w", err)
	}

	k.TTL, err = time.ParseDuration(string(parts[dataParts-2]))
	if err != nil {
		return fmt.Errorf("invalid ttl: %w", err)
	}

	rest := parts[dataParts-1]

	if len(rest) < encryptionSeedSize+publicKeySize+privateKeySize {
		return fmt.Errorf("invalid packed key size")
	}

	k.seed = rest[:encryptionSeedSize]

	k.publicKey, k.privateKey = k.getKeyInstance()

	pubKeyBytes := rest[encryptionSeedSize : encryptionSeedSize+publicKeySize]
	privKeyBytes := rest[encryptionSeedSize+publicKeySize:]

	k.publicKey.Unpack(pubKeyBytes)
	k.privateKey.Unpack(privKeyBytes)

	return nil
}

func (k *KyberKey) getByteFrames() (int, int, int) {
	var plaintextSize, ciphertextSize, seedSize int
	switch k.size {
	case Size1024:
		plaintextSize = kyber1024.PlaintextSize
		ciphertextSize = kyber1024.CiphertextSize
		seedSize = kyber1024.EncryptionSeedSize

	case Size512:
		plaintextSize = kyber512.PlaintextSize
		ciphertextSize = kyber512.CiphertextSize
		seedSize = kyber512.EncryptionSeedSize

	case Size768:
		plaintextSize = kyber768.PlaintextSize
		ciphertextSize = kyber768.CiphertextSize
		seedSize = kyber768.EncryptionSeedSize

	}
	return plaintextSize, ciphertextSize, seedSize
}

// getKeyFrames returns the sizes of the public and private keys in bytes.
func (k *KyberKey) getKeyFrames() (int, int) {
	var publicKeySize, privateKeySize int
	switch k.size {
	case Size1024:
		publicKeySize = kyber1024.PublicKeySize
		privateKeySize = kyber1024.PrivateKeySize

	case Size512:
		publicKeySize = kyber512.PublicKeySize
		privateKeySize = kyber512.PrivateKeySize

	case Size768:
		publicKeySize = kyber768.PublicKeySize
		privateKeySize = kyber768.PrivateKeySize
	}
	return publicKeySize, privateKeySize
}

func (k *KyberKey) getKeyInstance() (kyberPublicKey, kyberPrivateKey) {
	switch k.size {
	case Size1024:
		return &kyber1024.PublicKey{}, &kyber1024.PrivateKey{}
	case Size512:
		return &kyber512.PublicKey{}, &kyber512.PrivateKey{}
	case Size768:
		return &kyber768.PublicKey{}, &kyber768.PrivateKey{}
	default:
		return nil, nil
	}
}
