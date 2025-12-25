package trix_test

import (
	"bytes"
	"testing"

	"github.com/Snider/Enchantrix/pkg/trix"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptPayload_Good(t *testing.T) {
	t.Run("BasicEncryption", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 1)
		}

		originalPayload := []byte("This is a secret message that should be encrypted.")
		trixContainer := &trix.Trix{
			Header:  map[string]interface{}{"content_type": "text/plain"},
			Payload: originalPayload,
		}

		config := &trix.CryptoConfig{Key: key}
		err := trixContainer.EncryptPayload(config)
		require.NoError(t, err)

		// Verify encryption occurred
		assert.True(t, trixContainer.IsEncrypted())
		assert.Equal(t, trix.AlgorithmChaCha20Poly1305, trixContainer.GetEncryptionAlgorithm())
		assert.NotEqual(t, originalPayload, trixContainer.Payload)

		// Verify header metadata
		assert.Equal(t, true, trixContainer.Header[trix.HeaderKeyEncrypted])
		assert.Equal(t, trix.AlgorithmChaCha20Poly1305, trixContainer.Header[trix.HeaderKeyAlgorithm])
		assert.Equal(t, trix.ObfuscatorXOR, trixContainer.Header[trix.HeaderKeyObfuscator])
		assert.NotEmpty(t, trixContainer.Header[trix.HeaderKeyEncryptedAt])

		// Verify NO nonce in header (this is the key improvement over demo-style)
		_, hasNonce := trixContainer.Header["nonce"]
		assert.False(t, hasNonce, "nonce should NOT be stored in header")
	})

	t.Run("WithShuffleMaskObfuscator", func(t *testing.T) {
		key := make([]byte, 32)
		payload := []byte("test data")
		trixContainer := &trix.Trix{
			Header:  map[string]interface{}{},
			Payload: payload,
		}

		config := &trix.CryptoConfig{
			Key:        key,
			Obfuscator: trix.ObfuscatorShuffleMask,
		}
		err := trixContainer.EncryptPayload(config)
		require.NoError(t, err)

		assert.Equal(t, trix.ObfuscatorShuffleMask, trixContainer.Header[trix.HeaderKeyObfuscator])
	})

	t.Run("WithNilHeader", func(t *testing.T) {
		key := make([]byte, 32)
		trixContainer := &trix.Trix{
			Payload: []byte("test"),
		}

		config := &trix.CryptoConfig{Key: key}
		err := trixContainer.EncryptPayload(config)
		require.NoError(t, err)
		assert.NotNil(t, trixContainer.Header)
		assert.True(t, trixContainer.IsEncrypted())
	})
}

func TestEncryptPayload_Bad(t *testing.T) {
	t.Run("NilConfig", func(t *testing.T) {
		trixContainer := &trix.Trix{Payload: []byte("test")}
		err := trixContainer.EncryptPayload(nil)
		assert.ErrorIs(t, err, trix.ErrNoEncryptionKey)
	})

	t.Run("InvalidKeySize", func(t *testing.T) {
		trixContainer := &trix.Trix{Payload: []byte("test")}

		config := &trix.CryptoConfig{Key: []byte("too short")}
		err := trixContainer.EncryptPayload(config)
		assert.ErrorIs(t, err, trix.ErrNoEncryptionKey)
	})

	t.Run("AlreadyEncrypted", func(t *testing.T) {
		key := make([]byte, 32)
		trixContainer := &trix.Trix{
			Header:  map[string]interface{}{trix.HeaderKeyEncrypted: true},
			Payload: []byte("test"),
		}

		config := &trix.CryptoConfig{Key: key}
		err := trixContainer.EncryptPayload(config)
		assert.ErrorIs(t, err, trix.ErrAlreadyEncrypted)
	})
}

func TestDecryptPayload_Good(t *testing.T) {
	t.Run("BasicDecryption", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 1)
		}

		originalPayload := []byte("This is a secret message that should be encrypted.")
		trixContainer := &trix.Trix{
			Header:  map[string]interface{}{},
			Payload: originalPayload,
		}

		config := &trix.CryptoConfig{Key: key}

		// Encrypt
		err := trixContainer.EncryptPayload(config)
		require.NoError(t, err)
		assert.True(t, trixContainer.IsEncrypted())

		// Decrypt
		err = trixContainer.DecryptPayload(config)
		require.NoError(t, err)
		assert.False(t, trixContainer.IsEncrypted())
		assert.Equal(t, originalPayload, trixContainer.Payload)
	})

	t.Run("WithShuffleMaskObfuscator", func(t *testing.T) {
		key := make([]byte, 32)
		originalPayload := []byte("test with shuffle mask")
		trixContainer := &trix.Trix{
			Header:  map[string]interface{}{},
			Payload: originalPayload,
		}

		config := &trix.CryptoConfig{
			Key:        key,
			Obfuscator: trix.ObfuscatorShuffleMask,
		}

		err := trixContainer.EncryptPayload(config)
		require.NoError(t, err)

		err = trixContainer.DecryptPayload(config)
		require.NoError(t, err)
		assert.Equal(t, originalPayload, trixContainer.Payload)
	})

	t.Run("EmptyPayload", func(t *testing.T) {
		key := make([]byte, 32)
		trixContainer := &trix.Trix{
			Header:  map[string]interface{}{},
			Payload: []byte{},
		}

		config := &trix.CryptoConfig{Key: key}

		err := trixContainer.EncryptPayload(config)
		require.NoError(t, err)

		err = trixContainer.DecryptPayload(config)
		require.NoError(t, err)
		assert.Equal(t, []byte{}, trixContainer.Payload)
	})
}

func TestDecryptPayload_Bad(t *testing.T) {
	t.Run("NilConfig", func(t *testing.T) {
		trixContainer := &trix.Trix{
			Header:  map[string]interface{}{trix.HeaderKeyEncrypted: true},
			Payload: []byte("encrypted data"),
		}
		err := trixContainer.DecryptPayload(nil)
		assert.ErrorIs(t, err, trix.ErrNoEncryptionKey)
	})

	t.Run("InvalidKeySize", func(t *testing.T) {
		trixContainer := &trix.Trix{
			Header:  map[string]interface{}{trix.HeaderKeyEncrypted: true},
			Payload: []byte("encrypted data"),
		}

		config := &trix.CryptoConfig{Key: []byte("too short")}
		err := trixContainer.DecryptPayload(config)
		assert.ErrorIs(t, err, trix.ErrNoEncryptionKey)
	})

	t.Run("NotEncrypted", func(t *testing.T) {
		key := make([]byte, 32)
		trixContainer := &trix.Trix{
			Header:  map[string]interface{}{},
			Payload: []byte("not encrypted"),
		}

		config := &trix.CryptoConfig{Key: key}
		err := trixContainer.DecryptPayload(config)
		assert.ErrorIs(t, err, trix.ErrNotEncrypted)
	})

	t.Run("WrongKey", func(t *testing.T) {
		key1 := make([]byte, 32)
		key2 := make([]byte, 32)
		key2[0] = 1

		trixContainer := &trix.Trix{
			Header:  map[string]interface{}{},
			Payload: []byte("secret"),
		}

		config1 := &trix.CryptoConfig{Key: key1}
		err := trixContainer.EncryptPayload(config1)
		require.NoError(t, err)

		config2 := &trix.CryptoConfig{Key: key2}
		err = trixContainer.DecryptPayload(config2)
		assert.Error(t, err)
	})
}

func TestDecryptPayload_Ugly(t *testing.T) {
	t.Run("MissingObfuscatorHeader", func(t *testing.T) {
		key := make([]byte, 32)
		trixContainer := &trix.Trix{
			Header:  map[string]interface{}{},
			Payload: []byte("test"),
		}

		config := &trix.CryptoConfig{Key: key}
		err := trixContainer.EncryptPayload(config)
		require.NoError(t, err)

		// Remove the obfuscator header
		delete(trixContainer.Header, trix.HeaderKeyObfuscator)

		// Should still work with default XOR obfuscator
		err = trixContainer.DecryptPayload(config)
		require.NoError(t, err)
	})
}

func TestNewEncryptedTrix_Good(t *testing.T) {
	t.Run("Basic", func(t *testing.T) {
		key := make([]byte, 32)
		payload := []byte("secret message")
		header := map[string]interface{}{"custom": "value"}

		trixContainer, err := trix.NewEncryptedTrix(payload, key, header)
		require.NoError(t, err)

		assert.True(t, trixContainer.IsEncrypted())
		assert.Equal(t, "value", trixContainer.Header["custom"])
		assert.NotEqual(t, payload, trixContainer.Payload)
	})

	t.Run("WithNilHeader", func(t *testing.T) {
		key := make([]byte, 32)
		payload := []byte("secret message")

		trixContainer, err := trix.NewEncryptedTrix(payload, key, nil)
		require.NoError(t, err)

		assert.True(t, trixContainer.IsEncrypted())
		assert.NotNil(t, trixContainer.Header)
	})
}

func TestNewEncryptedTrix_Bad(t *testing.T) {
	t.Run("InvalidKey", func(t *testing.T) {
		_, err := trix.NewEncryptedTrix([]byte("test"), []byte("short"), nil)
		assert.Error(t, err)
	})
}

func TestIsEncrypted(t *testing.T) {
	t.Run("NilHeader", func(t *testing.T) {
		trixContainer := &trix.Trix{}
		assert.False(t, trixContainer.IsEncrypted())
	})

	t.Run("MissingKey", func(t *testing.T) {
		trixContainer := &trix.Trix{Header: map[string]interface{}{}}
		assert.False(t, trixContainer.IsEncrypted())
	})

	t.Run("FalseValue", func(t *testing.T) {
		trixContainer := &trix.Trix{
			Header: map[string]interface{}{trix.HeaderKeyEncrypted: false},
		}
		assert.False(t, trixContainer.IsEncrypted())
	})

	t.Run("TrueValue", func(t *testing.T) {
		trixContainer := &trix.Trix{
			Header: map[string]interface{}{trix.HeaderKeyEncrypted: true},
		}
		assert.True(t, trixContainer.IsEncrypted())
	})

	t.Run("WrongType", func(t *testing.T) {
		trixContainer := &trix.Trix{
			Header: map[string]interface{}{trix.HeaderKeyEncrypted: "true"},
		}
		assert.False(t, trixContainer.IsEncrypted())
	})
}

func TestGetEncryptionAlgorithm(t *testing.T) {
	t.Run("NilHeader", func(t *testing.T) {
		trixContainer := &trix.Trix{}
		assert.Empty(t, trixContainer.GetEncryptionAlgorithm())
	})

	t.Run("MissingKey", func(t *testing.T) {
		trixContainer := &trix.Trix{Header: map[string]interface{}{}}
		assert.Empty(t, trixContainer.GetEncryptionAlgorithm())
	})

	t.Run("ValidAlgorithm", func(t *testing.T) {
		trixContainer := &trix.Trix{
			Header: map[string]interface{}{trix.HeaderKeyAlgorithm: "test-algo"},
		}
		assert.Equal(t, "test-algo", trixContainer.GetEncryptionAlgorithm())
	})

	t.Run("WrongType", func(t *testing.T) {
		trixContainer := &trix.Trix{
			Header: map[string]interface{}{trix.HeaderKeyAlgorithm: 123},
		}
		assert.Empty(t, trixContainer.GetEncryptionAlgorithm())
	})
}

func TestEncryptedTrixRoundTrip(t *testing.T) {
	t.Run("FullRoundTrip", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i * 3)
		}

		originalPayload := []byte("This is the original secret message that will be encrypted, stored, and decrypted.")
		header := map[string]interface{}{
			"content_type": "text/plain",
			"custom_field": "custom_value",
		}

		// Create encrypted Trix
		config := &trix.CryptoConfig{Key: key}
		trixContainer := &trix.Trix{
			Header:  header,
			Payload: originalPayload,
		}

		err := trixContainer.EncryptPayload(config)
		require.NoError(t, err)

		// Encode to binary format
		encoded, err := trix.Encode(trixContainer, "ENCR", nil)
		require.NoError(t, err)

		// Decode from binary format
		decoded, err := trix.Decode(encoded, "ENCR", nil)
		require.NoError(t, err)

		// Verify still encrypted after decode
		assert.True(t, decoded.IsEncrypted())

		// Decrypt
		err = decoded.DecryptPayload(config)
		require.NoError(t, err)

		// Verify payload matches original
		assert.Equal(t, originalPayload, decoded.Payload)
		assert.Equal(t, "custom_value", decoded.Header["custom_field"])
	})
}

func TestNonceNotInHeader(t *testing.T) {
	t.Run("NonceEmbeddedNotExposed", func(t *testing.T) {
		key := make([]byte, 32)
		trixContainer := &trix.Trix{
			Header:  map[string]interface{}{},
			Payload: []byte("secret data"),
		}

		config := &trix.CryptoConfig{Key: key}
		err := trixContainer.EncryptPayload(config)
		require.NoError(t, err)

		// Verify nonce is NOT in header
		_, hasNonce := trixContainer.Header["nonce"]
		assert.False(t, hasNonce)

		// But the ciphertext contains the nonce (first 24 bytes)
		assert.GreaterOrEqual(t, len(trixContainer.Payload), 24)

		// Encode and decode
		encoded, err := trix.Encode(trixContainer, "TEST", nil)
		require.NoError(t, err)

		decoded, err := trix.Decode(encoded, "TEST", nil)
		require.NoError(t, err)

		// Still no nonce in header after decode
		_, hasNonce = decoded.Header["nonce"]
		assert.False(t, hasNonce)

		// But decryption still works (nonce is embedded in payload)
		err = decoded.DecryptPayload(config)
		require.NoError(t, err)
		assert.Equal(t, []byte("secret data"), decoded.Payload)
	})
}

func TestPlaintextNotExposed(t *testing.T) {
	t.Run("CleartextNeverInCiphertext", func(t *testing.T) {
		key := make([]byte, 32)
		distinctivePayload := []byte("DISTINCTIVE_SECRET_PATTERN_THAT_SHOULD_NOT_APPEAR")

		trixContainer := &trix.Trix{
			Header:  map[string]interface{}{},
			Payload: distinctivePayload,
		}

		config := &trix.CryptoConfig{Key: key}
		err := trixContainer.EncryptPayload(config)
		require.NoError(t, err)

		// The plaintext should not appear in the encrypted payload
		assert.False(t, bytes.Contains(trixContainer.Payload, distinctivePayload))
		assert.False(t, bytes.Contains(trixContainer.Payload, []byte("DISTINCTIVE")))
		assert.False(t, bytes.Contains(trixContainer.Payload, []byte("SECRET")))
		assert.False(t, bytes.Contains(trixContainer.Payload, []byte("PATTERN")))
	})
}
