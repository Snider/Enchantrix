
package pgp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_GenerateKeyPair_Good(t *testing.T) {
	s := NewService()
	pub, priv, err := s.GenerateKeyPair("test", "test@test.com", "test")
	require.NoError(t, err, "failed to generate key pair")
	assert.NotNil(t, pub, "public key is nil")
	assert.NotNil(t, priv, "private key is nil")
}

func TestService_Encrypt_Good(t *testing.T) {
	s := NewService()
	pub, priv, err := s.GenerateKeyPair("test", "test@test.com", "test")
	require.NoError(t, err, "failed to generate key pair")
	assert.NotNil(t, pub, "public key is nil")
	assert.NotNil(t, priv, "private key is nil")

	data := []byte("hello world")
	encrypted, err := s.Encrypt(pub, data)
	require.NoError(t, err, "failed to encrypt data")
	assert.NotNil(t, encrypted, "encrypted data is nil")
}

func TestService_Decrypt_Good(t *testing.T) {
	s := NewService()
	pub, priv, err := s.GenerateKeyPair("test", "test@test.com", "test")
	require.NoError(t, err, "failed to generate key pair")
	assert.NotNil(t, pub, "public key is nil")
	assert.NotNil(t, priv, "private key is nil")

	data := []byte("hello world")
	encrypted, err := s.Encrypt(pub, data)
	require.NoError(t, err, "failed to encrypt data")
	assert.NotNil(t, encrypted, "encrypted data is nil")

	decrypted, err := s.Decrypt(priv, encrypted)
	require.NoError(t, err, "failed to decrypt data")
	assert.Equal(t, data, decrypted, "decrypted data does not match original")
}

func TestService_Sign_Good(t *testing.T) {
	s := NewService()
	pub, priv, err := s.GenerateKeyPair("test", "test@test.com", "test")
	require.NoError(t, err, "failed to generate key pair")
	assert.NotNil(t, pub, "public key is nil")
	assert.NotNil(t, priv, "private key is nil")

	data := []byte("hello world")
	signature, err := s.Sign(priv, data)
	require.NoError(t, err, "failed to sign data")
	assert.NotNil(t, signature, "signature is nil")
}

func TestService_Verify_Good(t *testing.T) {
	s := NewService()
	pub, priv, err := s.GenerateKeyPair("test", "test@test.com", "test")
	require.NoError(t, err, "failed to generate key pair")
	assert.NotNil(t, pub, "public key is nil")
	assert.NotNil(t, priv, "private key is nil")

	data := []byte("hello world")
	signature, err := s.Sign(priv, data)
	require.NoError(t, err, "failed to sign data")
	assert.NotNil(t, signature, "signature is nil")

	err = s.Verify(pub, data, signature)
	require.NoError(t, err, "failed to verify signature")
}

func TestService_SymmetricallyEncrypt_Good(t *testing.T) {
	s := NewService()
	passphrase := []byte("hello world")
	data := []byte("hello world")
	encrypted, err := s.SymmetricallyEncrypt(passphrase, data)
	require.NoError(t, err, "failed to encrypt data")
	assert.NotNil(t, encrypted, "encrypted data is nil")
}
