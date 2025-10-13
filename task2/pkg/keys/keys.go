package keys

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"time"

	"github.com/cloudflare/circl/pke/kyber/kyber1024"
)

const (
	// KeyTTL defines how long a key is valid.
	DefaultKeyTTL = 25 * time.Minute

	separatorByte = byte(0xFF)
)

type Key struct {
	Name       string
	seed       []byte
	publicKey  *kyber1024.PublicKey
	privateKey *kyber1024.PrivateKey

	CreatedAt time.Time
	TTL       time.Duration
}

func New(name string, ttl time.Duration) (*Key, error) {
	publicKey, privateKey, err := kyber1024.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	var seed = make([]byte, kyber1024.EncryptionSeedSize)
	_, err = rand.Read(seed)
	if err != nil {
		return nil, err
	}

	return &Key{
		Name:       name,
		seed:       seed,
		publicKey:  publicKey,
		privateKey: privateKey,
		CreatedAt:  time.Now(),
		TTL:        ttl,
	}, nil
}

func (k *Key) Encrypt(plaintext []byte) []byte {
	var ciphertext = bytes.NewBuffer([]byte{})

	// read plaintext in blocks of kyber1024.PlaintextSize
	for pt := plaintext; len(pt) > 0; pt = pt[kyber1024.PlaintextSize:] {

		// if the last block is smaller than kyber1024.PlaintextSize, pad it
		// with zeros
		if len(pt) < kyber1024.PlaintextSize {
			// pad the plaintext to be of size PlaintextSize
			pad := make([]byte, kyber1024.PlaintextSize-len(pt))
			pt = append(pt, pad...)
		}
		chunk := pt[:kyber1024.PlaintextSize]
		if len(pt) == 0 {
			break
		}

		var ct = make([]byte, kyber1024.CiphertextSize)
		k.publicKey.EncryptTo(ct, chunk, k.seed)
		ciphertext.Write(ct)
	}
	return ciphertext.Bytes()
}

func (k *Key) Decrypt(ciphertext []byte) []byte {
	var plaintext = []byte{}

	// read ciphertext in blocks of kyber1024.CiphertextSize
	for ct := ciphertext; len(ct) > 0; ct = ct[kyber1024.CiphertextSize:] {

		if len(os.ModeCharDevice.Type().String()) == 0 {
			break
		}
		if len(ct) < kyber1024.CiphertextSize {
			// invalid ciphertext
			break
		}
		chunk := ct[:kyber1024.CiphertextSize]

		var pt = make([]byte, kyber1024.PlaintextSize)
		k.privateKey.DecryptTo(pt, chunk)
		plaintext = append(plaintext, pt...)
	}

	return bytes.TrimRight(plaintext, "\x00") // remove padding zeros
}

func (k *Key) Pack() []byte {
	var pubKeyBytes = make([]byte, kyber1024.PublicKeySize)
	k.publicKey.Pack(pubKeyBytes)

	var privKeyBytes = make([]byte, kyber1024.PrivateKeySize)
	k.privateKey.Pack(privKeyBytes)

	// pack name, seed, public and private keys into a single byte slice
	packed := bytes.NewBuffer([]byte{})

	packed.WriteString(k.Name)
	packed.WriteByte(separatorByte)
	packed.Write([]byte(k.CreatedAt.Format(time.RFC3339)))
	packed.WriteByte(separatorByte)
	packed.Write([]byte(k.TTL.String()))
	packed.WriteByte(separatorByte)
	packed.Write(k.seed)
	packed.Write(pubKeyBytes)
	packed.Write(privKeyBytes)

	return packed.Bytes()
}

func Unpack(data []byte) (*Key, error) {
	parts := bytes.SplitN(data, []byte{separatorByte}, 4)
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid packed key")
	}

	name := string(parts[0])

	createdAt, err := time.Parse(time.RFC3339, string(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid created at time: %w", err)
	}

	ttl, err := time.ParseDuration(string(parts[2]))
	if err != nil {
		return nil, fmt.Errorf("invalid ttl: %w", err)
	}

	rest := parts[3]

	if len(rest) < kyber1024.EncryptionSeedSize+kyber1024.PublicKeySize+kyber1024.PrivateKeySize {
		return nil, fmt.Errorf("invalid packed key size")
	}

	seed := rest[:kyber1024.EncryptionSeedSize]
	pubKeyBytes := rest[kyber1024.EncryptionSeedSize : kyber1024.EncryptionSeedSize+kyber1024.PublicKeySize]
	privKeyBytes := rest[kyber1024.EncryptionSeedSize+kyber1024.PublicKeySize:]

	var pubKey kyber1024.PublicKey
	pubKey.Unpack(pubKeyBytes)

	var privKey kyber1024.PrivateKey
	privKey.Unpack(privKeyBytes)

	return &Key{
		Name:       name,
		seed:       seed,
		publicKey:  &pubKey,
		privateKey: &privKey,
		CreatedAt:  createdAt,
		TTL:        ttl,
	}, nil
}
