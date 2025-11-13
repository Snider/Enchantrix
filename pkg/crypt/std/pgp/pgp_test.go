
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
	pub, _, err := s.GenerateKeyPair("test", "test@test.com", "test")
	require.NoError(t, err, "failed to generate key pair")
	assert.NotNil(t, pub, "public key is nil")

	data := []byte("hello world")
	encrypted, err := s.Encrypt(pub, data)
	require.NoError(t, err, "failed to encrypt data")
	assert.NotNil(t, encrypted, "encrypted data is nil")
}

func TestService_Encrypt_Bad(t *testing.T) {
	s := NewService()
	_, err := s.Encrypt([]byte("bad key"), []byte("hello world"))
	assert.Error(t, err)
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

func TestService_Decrypt_Bad(t *testing.T) {
	s := NewService()
	_, err := s.Decrypt([]byte("bad key"), []byte("hello world"))
	assert.Error(t, err)

	pub, _, err := s.GenerateKeyPair("test", "test@test.com", "test")
	require.NoError(t, err)
	_, priv2, err := s.GenerateKeyPair("test2", "test2@test.com", "test2")
	require.NoError(t, err)
	encrypted, err := s.Encrypt(pub, []byte("hello world"))
	require.NoError(t, err)
	_, err = s.Decrypt(priv2, encrypted)
	assert.Error(t, err)
}

func TestService_Sign_Good(t *testing.T) {
	s := NewService()
	_, priv, err := s.GenerateKeyPair("test", "test@test.com", "test")
	require.NoError(t, err, "failed to generate key pair")
	assert.NotNil(t, priv, "private key is nil")

	data := []byte("hello world")
	signature, err := s.Sign(priv, data)
	require.NoError(t, err, "failed to sign data")
	assert.NotNil(t, signature, "signature is nil")
}

func TestService_Sign_Bad(t *testing.T) {
	s := NewService()
	_, err := s.Sign([]byte("bad key"), []byte("hello world"))
	assert.Error(t, err)
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

func TestService_Verify_Bad(t *testing.T) {
	s := NewService()
	err := s.Verify([]byte("bad key"), []byte("hello world"), []byte("bad signature"))
	assert.Error(t, err)

	_, priv, err := s.GenerateKeyPair("test", "test@test.com", "test")
	require.NoError(t, err)
	pub2, _, err := s.GenerateKeyPair("test2", "test2@test.com", "test2")
	require.NoError(t, err)
	signature, err := s.Sign(priv, []byte("hello world"))
	require.NoError(t, err)
	err = s.Verify(pub2, []byte("hello world"), signature)
	assert.Error(t, err)
}

func TestService_SymmetricallyEncrypt_Good(t *testing.T) {
	s := NewService()
	passphrase := []byte("hello world")
	data := []byte("hello world")
	encrypted, err := s.SymmetricallyEncrypt(passphrase, data)
	require.NoError(t, err, "failed to encrypt data")
	assert.NotNil(t, encrypted, "encrypted data is nil")
}
