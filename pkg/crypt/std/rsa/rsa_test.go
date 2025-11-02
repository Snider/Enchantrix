package rsa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRSA_Good(t *testing.T) {
	s := NewService()

	// Generate a new key pair
	pubKey, privKey, err := s.GenerateKeyPair(2048)
	assert.NoError(t, err)
	assert.NotEmpty(t, pubKey)
	assert.NotEmpty(t, privKey)

	// Encrypt and decrypt a message
	message := []byte("Hello, World!")
	ciphertext, err := s.Encrypt(pubKey, message, nil)
	assert.NoError(t, err)
	plaintext, err := s.Decrypt(privKey, ciphertext, nil)
	assert.NoError(t, err)
	assert.Equal(t, message, plaintext)
}

func TestRSA_Bad(t *testing.T) {
	s := NewService()

	// Decrypt with wrong key
	pubKey, _, err := s.GenerateKeyPair(2048)
	assert.NoError(t, err)
	_, otherPrivKey, err := s.GenerateKeyPair(2048)
	assert.NoError(t, err)
	message := []byte("Hello, World!")
	ciphertext, err := s.Encrypt(pubKey, message, nil)
	assert.NoError(t, err)
	_, err = s.Decrypt(otherPrivKey, ciphertext, nil)
	assert.Error(t, err)

	// Key size too small
	_, _, err = s.GenerateKeyPair(512)
	assert.Error(t, err)
}

func TestRSA_Ugly(t *testing.T) {
	s := NewService()

	// Malformed keys and messages
	_, err := s.Encrypt([]byte("not-a-key"), []byte("message"), nil)
	assert.Error(t, err)
	_, err = s.Decrypt([]byte("not-a-key"), []byte("message"), nil)
	assert.Error(t, err)
}
