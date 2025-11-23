
package pgp

import (
	"errors"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
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

func TestService_GenerateKeyPair_Bad(t *testing.T) {
	s := NewService()
	// Test with invalid name (null byte)
	_, _, err := s.GenerateKeyPair("test\x00", "test@test.com", "test")
	assert.Error(t, err)
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

func TestService_SymmetricallyEncrypt_Bad(t *testing.T) {
	s := NewService()
	// Test with empty passphrase
	_, err := s.SymmetricallyEncrypt([]byte(""), []byte("hello world"))
	assert.Error(t, err)
}

func TestService_SymmetricallyDecrypt_Good(t *testing.T) {
	s := NewService()
	passphrase := []byte("hello world")
	data := []byte("hello world")
	encrypted, err := s.SymmetricallyEncrypt(passphrase, data)
	require.NoError(t, err, "failed to encrypt data")
	assert.NotNil(t, encrypted, "encrypted data is nil")

	decrypted, err := s.SymmetricallyDecrypt(passphrase, encrypted)
	require.NoError(t, err, "failed to decrypt data")
	assert.Equal(t, data, decrypted, "decrypted data does not match original")
}

func TestService_SymmetricallyDecrypt_Bad(t *testing.T) {
	s := NewService()
	// Test with empty passphrase
	_, err := s.SymmetricallyDecrypt([]byte(""), []byte("hello world"))
	assert.Error(t, err)

	// Test with wrong passphrase
	passphrase := []byte("hello world")
	data := []byte("hello world")
	encrypted, err := s.SymmetricallyEncrypt(passphrase, data)
	require.NoError(t, err, "failed to encrypt data")

	_, err = s.SymmetricallyDecrypt([]byte("wrong passphrase"), encrypted)
	assert.Error(t, err)

	// Test with bad encrypted data
	_, err = s.SymmetricallyDecrypt(passphrase, []byte("bad encrypted data"))
	assert.Error(t, err)

	// Test with corrupt body
	pub3, priv3, err := s.GenerateKeyPair("test3", "test3@test.com", "test3")
	require.NoError(t, err)
	encrypted3, err := s.Encrypt(pub3, []byte("hello world"))
	require.NoError(t, err)
	encrypted3[len(encrypted3)-1] ^= 0x01
	_, err = s.Decrypt(priv3, encrypted3)
	assert.Error(t, err)
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

	_, err = s.Decrypt(priv2, []byte("bad encrypted data"))
	assert.Error(t, err)

	// Test with corrupt body
	pub3, priv3, err := s.GenerateKeyPair("test3", "test3@test.com", "test3")
	require.NoError(t, err)
	encrypted3, err := s.Encrypt(pub3, []byte("hello world"))
	require.NoError(t, err)
	encrypted3[len(encrypted3)-1] ^= 0x01
	_, err = s.Decrypt(priv3, encrypted3)
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

	// Test with public key (no private key)
	pub, _, err := s.GenerateKeyPair("test", "test@test.com", "test")
	require.NoError(t, err)
	_, err = s.Sign(pub, []byte("hello world"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private key not found")
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

// Mock testing infrastructure

type mockWriteCloser struct {
	writeFunc func(p []byte) (n int, err error)
	closeFunc func() error
}

func (m *mockWriteCloser) Write(p []byte) (n int, err error) {
	if m.writeFunc != nil {
		return m.writeFunc(p)
	}
	return len(p), nil
}

func (m *mockWriteCloser) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

type mockReader struct {
	readFunc func(p []byte) (n int, err error)
}

func (m *mockReader) Read(p []byte) (n int, err error) {
	if m.readFunc != nil {
		return m.readFunc(p)
	}
	return 0, io.EOF
}

func TestService_GenerateKeyPair_MockErrors(t *testing.T) {
	s := NewService()
	origNewEntity := openpgpNewEntity
	origArmorEncode := armorEncode
	defer func() {
		openpgpNewEntity = origNewEntity
		armorEncode = origArmorEncode
	}()

	// 1. Mock NewEntity error
	openpgpNewEntity = func(name, comment, email string, config *packet.Config) (*openpgp.Entity, error) {
		return nil, errors.New("mock new entity error")
	}
	_, _, err := s.GenerateKeyPair("test", "test", "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock new entity error")
	openpgpNewEntity = origNewEntity // restore

	// 2. Mock armorEncode error (public key)
	armorEncode = func(out io.Writer, typeStr string, headers map[string]string) (io.WriteCloser, error) {
		if typeStr == openpgp.PublicKeyType {
			return nil, errors.New("mock armor pub error")
		}
		return origArmorEncode(out, typeStr, headers)
	}
	_, _, err = s.GenerateKeyPair("test", "test", "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock armor pub error")
	armorEncode = origArmorEncode // restore

	// 3. Mock armorEncode error (private key)
	armorEncode = func(out io.Writer, typeStr string, headers map[string]string) (io.WriteCloser, error) {
		if typeStr == openpgp.PrivateKeyType {
			return nil, errors.New("mock armor priv error")
		}
		return origArmorEncode(out, typeStr, headers)
	}
	_, _, err = s.GenerateKeyPair("test", "test", "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock armor priv error")
	armorEncode = origArmorEncode // restore

	// 4. Mock Serialize error (via Write failure)
	// We need armorEncode to return a writer that fails on Write
	armorEncode = func(out io.Writer, typeStr string, headers map[string]string) (io.WriteCloser, error) {
		if typeStr == openpgp.PublicKeyType {
			return &mockWriteCloser{
				writeFunc: func(p []byte) (n int, err error) {
					return 0, errors.New("mock write pub error")
				},
			}, nil
		}
		return origArmorEncode(out, typeStr, headers)
	}
	_, _, err = s.GenerateKeyPair("test", "test", "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock write pub error")
	armorEncode = origArmorEncode // restore

	// 5. Mock SerializePrivate error (via Write failure)
	armorEncode = func(out io.Writer, typeStr string, headers map[string]string) (io.WriteCloser, error) {
		if typeStr == openpgp.PrivateKeyType {
			return &mockWriteCloser{
				writeFunc: func(p []byte) (n int, err error) {
					return 0, errors.New("mock write priv error")
				},
			}, nil
		}
		return origArmorEncode(out, typeStr, headers)
	}
	_, _, err = s.GenerateKeyPair("test", "test", "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock write priv error")
	armorEncode = origArmorEncode // restore
}


func TestService_Encrypt_MockErrors(t *testing.T) {
	s := NewService()
	pub, _, err := s.GenerateKeyPair("test", "test", "test")
	require.NoError(t, err)

	origEncrypt := openpgpEncrypt
	defer func() { openpgpEncrypt = origEncrypt }()

	// 1. Mock Encrypt error
	openpgpEncrypt = func(ciphertext io.Writer, to []*openpgp.Entity, signed *openpgp.Entity, hints *openpgp.FileHints, config *packet.Config) (io.WriteCloser, error) {
		return nil, errors.New("mock encrypt error")
	}
	_, err = s.Encrypt(pub, []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock encrypt error")

	// 2. Mock Write error
	openpgpEncrypt = func(ciphertext io.Writer, to []*openpgp.Entity, signed *openpgp.Entity, hints *openpgp.FileHints, config *packet.Config) (io.WriteCloser, error) {
		return &mockWriteCloser{
			writeFunc: func(p []byte) (n int, err error) {
				return 0, errors.New("mock write data error")
			},
		}, nil
	}
	_, err = s.Encrypt(pub, []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock write data error")
}

func TestService_Sign_MockErrors(t *testing.T) {
	s := NewService()
	_, priv, err := s.GenerateKeyPair("test", "test", "test")
	require.NoError(t, err)

	origSign := openpgpArmoredDetachSign
	defer func() { openpgpArmoredDetachSign = origSign }()

	// Mock Sign error
	openpgpArmoredDetachSign = func(w io.Writer, signer *openpgp.Entity, message io.Reader, config *packet.Config) error {
		return errors.New("mock sign error")
	}
	_, err = s.Sign(priv, []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock sign error")
}

func TestService_SymmetricallyEncrypt_MockErrors(t *testing.T) {
	s := NewService()

	origSymEncrypt := openpgpSymmetricallyEncrypt
	defer func() { openpgpSymmetricallyEncrypt = origSymEncrypt }()

	// 1. Mock Sym Encrypt error
	openpgpSymmetricallyEncrypt = func(ciphertext io.Writer, passphrase []byte, hints *openpgp.FileHints, config *packet.Config) (io.WriteCloser, error) {
		return nil, errors.New("mock sym encrypt error")
	}
	_, err := s.SymmetricallyEncrypt([]byte("pass"), []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock sym encrypt error")

	// 2. Mock Write error
	openpgpSymmetricallyEncrypt = func(ciphertext io.Writer, passphrase []byte, hints *openpgp.FileHints, config *packet.Config) (io.WriteCloser, error) {
		return &mockWriteCloser{
			writeFunc: func(p []byte) (n int, err error) {
				return 0, errors.New("mock sym write error")
			},
		}, nil
	}
	_, err = s.SymmetricallyEncrypt([]byte("pass"), []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock sym write error")
}

func TestService_SymmetricallyDecrypt_MockErrors(t *testing.T) {
	s := NewService()
	pass := []byte("pass")

	origReadMessage := openpgpReadMessage
	defer func() { openpgpReadMessage = origReadMessage }()

	// Mock ReadMessage error
	openpgpReadMessage = func(r io.Reader, keyring openpgp.KeyRing, prompt openpgp.PromptFunction, config *packet.Config) (*openpgp.MessageDetails, error) {
		return nil, errors.New("mock read message error")
	}
	_, err := s.SymmetricallyDecrypt(pass, []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock read message error")

	// Mock ReadAll error (via ReadMessage returning bad body)
	openpgpReadMessage = func(r io.Reader, keyring openpgp.KeyRing, prompt openpgp.PromptFunction, config *packet.Config) (*openpgp.MessageDetails, error) {
		// We need to return a message with UnverifiedBody that fails on Read
		return &openpgp.MessageDetails{
			UnverifiedBody: &mockReader{
				readFunc: func(p []byte) (n int, err error) {
					return 0, errors.New("mock read body error")
				},
			},
		}, nil
	}
	_, err = s.SymmetricallyDecrypt(pass, []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock read body error")
}
