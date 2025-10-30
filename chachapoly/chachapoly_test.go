package chachapoly

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 1
	}

	plaintext := []byte("Hello, world!")
	ciphertext, err := Encrypt(plaintext, key)
	assert.NoError(t, err)

	decrypted, err := Decrypt(ciphertext, key)
	assert.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptInvalidKeySize(t *testing.T) {
	key := make([]byte, 16) // Wrong size
	plaintext := []byte("test")
	_, err := Encrypt(plaintext, key)
	assert.Error(t, err)
}

func TestDecryptWithWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1 // Different key

	plaintext := []byte("secret")
	ciphertext, err := Encrypt(plaintext, key1)
	assert.NoError(t, err)

	_, err = Decrypt(ciphertext, key2)
	assert.Error(t, err) // Should fail authentication
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("secret")
	ciphertext, err := Encrypt(plaintext, key)
	assert.NoError(t, err)

	// Tamper with the ciphertext
	ciphertext[0] ^= 0xff

	_, err = Decrypt(ciphertext, key)
	assert.Error(t, err)
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("")
	ciphertext, err := Encrypt(plaintext, key)
	assert.NoError(t, err)

	decrypted, err := Decrypt(ciphertext, key)
	assert.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestDecryptShortCiphertext(t *testing.T) {
	key := make([]byte, 32)
	shortCiphertext := []byte("short")

	_, err := Decrypt(shortCiphertext, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestCiphertextDiffersFromPlaintext(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("Hello, world!")
	ciphertext, err := Encrypt(plaintext, key)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)
}
