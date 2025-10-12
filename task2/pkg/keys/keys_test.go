package keys_test

import (
	"enclave-task2/pkg/keys"
	"os"
	"testing"

	"github.com/tj/assert"
)

func TestKeys(t *testing.T) {
	key, err := keys.New("test-key")
	assert.NoError(t, err)
	assert.NotNil(t, key)

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
}

func TestKeyFromFiles(t *testing.T) {
	// create a new key and save it to files
	err := os.MkdirAll("./file-keys/", 0700)
	assert.NoError(t, err)
	defer os.RemoveAll("./file-keys/")

	key, err := keys.New("file-key")
	assert.NoError(t, err)
	assert.NotNil(t, key)

	err = key.ToFile("./file-keys")
	assert.NoError(t, err)

	// load the key from files
	loadedKey, err := keys.KeyFromFiles("file-key", "./file-keys")
	assert.NoError(t, err)
	assert.NotNil(t, loadedKey)

	// ensure the loaded key can decrypt what the original key encrypted
	plaintext := []byte("File Key Test")
	ciphertext := key.Encrypt(plaintext)
	decrypted := loadedKey.Decrypt(ciphertext)
	assert.Equal(t, plaintext, decrypted)

	plaintext = []byte(`Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse viverra, leo et ullamcorper suscipit, velit ex pretium risus, ut convallis justo enim vel odio. Proin erat orci, euismod sed ultrices a, ullamcorper vitae sem. Etiam risus nisl, tempor non convallis quis, convallis at purus. Nulla euismod nisl nec vehicula consectetur. Aliquam ultricies dolor nec urna lobortis, vitae tincidunt odio rhoncus. Vestibulum ipsum augue, euismod et consequat ut, accumsan ut dui. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Nulla vitae sem lorem. Vestibulum quis mauris a lacus rhoncus gravida. Mauris fermentum rhoncus dolor et congue. Donec nec commodo dui.
	Cras sit amet molestie sem. Suspendisse interdum urna eu ipsum vestibulum tincidunt. Phasellus pretium pretium quam, at volutpat nisi bibendum nec. Nulla mattis ornare metus, vitae ultricies orci volutpat quis. Fusce ut tortor odio. In hac habitasse platea dictumst. Curabitur sit amet quam non odio gravida iaculis hendrerit rhoncus est. Sed ut consectetur odio, pellentesque dictum diam. Phasellus molestie lorem at convallis volutpat. Aenean dapibus pretium convallis. Etiam eget lacus leo. Nam volutpat erat quam, ut malesuada augue aliquam posuere. Nullam pharetra arcu non tincidunt auctor. Mauris varius augue a quam aliquam, at venenatis enim gravida. Nunc tincidunt lacus eget laoreet pulvinar. Aliquam posuere massa a orci sodales, eget dictum quam commodo.`)
	ciphertext = key.Encrypt(plaintext)
	decrypted = loadedKey.Decrypt(ciphertext)
	assert.Equal(t, plaintext, decrypted)
}

func TestKeysPackUnpack(t *testing.T) {
	key, err := keys.New("pack-key")
	assert.NoError(t, err)
	assert.NotNil(t, key)

	packed := key.Pack()
	assert.NotEmpty(t, packed)

	unpackedKey, err := keys.Unpack(packed)
	assert.NoError(t, err)
	assert.NotNil(t, unpackedKey)

	// ensure the unpacked key can decrypt what the original key encrypted
	plaintext := []byte("Pack Unpack Test")
	ciphertext := key.Encrypt(plaintext)
	decrypted := unpackedKey.Decrypt(ciphertext)
	assert.Equal(t, plaintext, decrypted)

	plaintext = []byte(`Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse viverra, leo et ullamcorper suscipit, velit ex pretium risus, ut convallis justo enim vel odio. Proin erat orci, euismod sed ultrices a, ullamcorper vitae sem. Etiam risus nisl, tempor non convallis quis, convallis at purus. Nulla euismod nisl nec vehicula consectetur. Aliquam ultricies dolor nec urna lobortis, vitae tincidunt odio rhoncus. Vestibulum ipsum augue, euismod et consequat ut, accumsan ut dui. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Nulla vitae sem lorem. Vestibulum quis mauris a lacus rhoncus gravida. Mauris fermentum rhoncus dolor et congue. Donec nec commodo dui.
	Cras sit amet molestie sem. Suspendisse interdum urna eu ipsum vestibulum tincidunt. Phasellus pretium pretium quam, at volutpat nisi bibendum nec. Nulla mattis ornare metus, vitae ultricies orci volutpat quis. Fusce ut tortor odio. In hac habitasse platea dictumst. Curabitur sit amet quam non odio gravida iaculis hendrerit rhoncus est. Sed ut consectetur odio, pellentesque dictum diam. Phasellus molestie lorem at convallis volutpat. Aenean dapibus pretium convallis. Etiam eget lacus leo. Nam volutpat erat quam, ut malesuada augue aliquam posuere. Nullam pharetra arcu non tincidunt auctor. Mauris varius augue a quam aliquam, at venenatis enim gravida. Nunc tincidunt lacus eget laoreet pulvinar. Aliquam posuere massa a orci sodales, eget dictum quam commodo.`)
	ciphertext = key.Encrypt(plaintext)
	decrypted = unpackedKey.Decrypt(ciphertext)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptKey(t *testing.T) {
	key, err := keys.New("encrypt-key")
	assert.NoError(t, err)
	assert.NotNil(t, key)

	plaintext := key.Pack()
	ciphertext := key.Encrypt(plaintext)
	assert.NotEmpty(t, ciphertext)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted := key.Decrypt(ciphertext)
	assert.Equal(t, plaintext, decrypted)
}
