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
