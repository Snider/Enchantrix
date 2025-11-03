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
	_, err = s.Encrypt([]byte("-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJ/6j/y7/r/9/z/8/f/+/v7+/v7+/v7+\nv/7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v4=\n-----END PUBLIC KEY-----"), []byte("message"), nil)
	assert.Error(t, err)
	_, err = s.Decrypt([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIBOQIBAAJBAL/6j/y7/r/9/z/8/f/+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+\nv/7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v4CAwEAAQJB\nAL/6j/y7/r/9/z/8/f/+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+\nv/7+/v7+/v7+/v7+/v7+/v7+/v7+/v4CgYEA/f8/vLv+v/3/P/z9//7+/v7+/v7+\nvv7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v4C\ngYEA/f8/vLv+v/3/P/z9//7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+\nvv7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v4CgYEA/f8/vLv+v/3/P/z9//7+/v7+\nvv7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+\nv/4CgYEA/f8/vLv+v/3/P/z9//7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+\nvv7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v4CgYEA/f8/vLv+v/3/P/z9//7+/v7+\nvv7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+\nv/4=\n-----END RSA PRIVATE KEY-----"), []byte("message"), nil)
	assert.Error(t, err)
}
