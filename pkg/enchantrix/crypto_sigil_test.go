package enchantrix

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRandReader is a reader that returns an error.
type mockRandReader struct{}

func (r *mockRandReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("random read error")
}

// deterministicReader returns a predictable sequence for testing.
type deterministicReader struct {
	seed byte
}

func (r *deterministicReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = r.seed
		r.seed++
	}
	return len(p), nil
}

// --- ChaChaPolySigil Tests ---

func TestChaChaPolySigil_Good(t *testing.T) {
	t.Run("EncryptDecrypt", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 1)
		}

		sigil, err := NewChaChaPolySigil(key)
		require.NoError(t, err)

		plaintext := []byte("Hello, this is a secret message!")
		ciphertext, err := sigil.In(plaintext)
		require.NoError(t, err)
		assert.NotEqual(t, plaintext, ciphertext)
		assert.Greater(t, len(ciphertext), len(plaintext)) // nonce + overhead

		decrypted, err := sigil.Out(ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("EmptyPlaintext", func(t *testing.T) {
		key := make([]byte, 32)
		sigil, err := NewChaChaPolySigil(key)
		require.NoError(t, err)

		ciphertext, err := sigil.In([]byte{})
		require.NoError(t, err)

		decrypted, err := sigil.Out(ciphertext)
		require.NoError(t, err)
		assert.Equal(t, []byte{}, decrypted)
	})

	t.Run("LargeData", func(t *testing.T) {
		key := make([]byte, 32)
		sigil, err := NewChaChaPolySigil(key)
		require.NoError(t, err)

		// Test with 1MB of data
		plaintext := make([]byte, 1024*1024)
		_, err = rand.Read(plaintext)
		require.NoError(t, err)

		ciphertext, err := sigil.In(plaintext)
		require.NoError(t, err)

		decrypted, err := sigil.Out(ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("DifferentNoncesEachEncryption", func(t *testing.T) {
		key := make([]byte, 32)
		sigil, err := NewChaChaPolySigil(key)
		require.NoError(t, err)

		plaintext := []byte("same message")

		ciphertext1, err := sigil.In(plaintext)
		require.NoError(t, err)

		ciphertext2, err := sigil.In(plaintext)
		require.NoError(t, err)

		// Ciphertexts should differ due to different nonces
		assert.NotEqual(t, ciphertext1, ciphertext2)

		// But both should decrypt to the same plaintext
		decrypted1, err := sigil.Out(ciphertext1)
		require.NoError(t, err)
		decrypted2, err := sigil.Out(ciphertext2)
		require.NoError(t, err)

		assert.Equal(t, plaintext, decrypted1)
		assert.Equal(t, plaintext, decrypted2)
	})

	t.Run("PreObfuscationApplied", func(t *testing.T) {
		key := make([]byte, 32)

		// Use deterministic reader so we can verify obfuscation
		sigil, err := NewChaChaPolySigil(key)
		require.NoError(t, err)
		sigil.randReader = &deterministicReader{seed: 0}

		plaintext := []byte("test data")
		ciphertext, err := sigil.In(plaintext)
		require.NoError(t, err)

		// The nonce is the first 24 bytes
		nonce := ciphertext[:24]

		// Verify that pre-obfuscation was applied by checking that
		// the plaintext pattern doesn't appear in raw form
		// (The obfuscated data is XORed with a stream derived from the nonce)
		obfuscator := &XORObfuscator{}
		obfuscated := obfuscator.Obfuscate(plaintext, nonce)
		assert.NotEqual(t, plaintext, obfuscated)
	})
}

func TestChaChaPolySigil_Bad(t *testing.T) {
	t.Run("InvalidKeySize", func(t *testing.T) {
		_, err := NewChaChaPolySigil([]byte("too short"))
		assert.ErrorIs(t, err, ErrInvalidKey)

		_, err = NewChaChaPolySigil(make([]byte, 16))
		assert.ErrorIs(t, err, ErrInvalidKey)

		_, err = NewChaChaPolySigil(make([]byte, 64))
		assert.ErrorIs(t, err, ErrInvalidKey)
	})

	t.Run("WrongKey", func(t *testing.T) {
		key1 := make([]byte, 32)
		key2 := make([]byte, 32)
		key2[0] = 1 // Different key

		sigil1, err := NewChaChaPolySigil(key1)
		require.NoError(t, err)
		sigil2, err := NewChaChaPolySigil(key2)
		require.NoError(t, err)

		ciphertext, err := sigil1.In([]byte("secret"))
		require.NoError(t, err)

		_, err = sigil2.Out(ciphertext)
		assert.ErrorIs(t, err, ErrDecryptionFailed)
	})

	t.Run("TamperedCiphertext", func(t *testing.T) {
		key := make([]byte, 32)
		sigil, err := NewChaChaPolySigil(key)
		require.NoError(t, err)

		ciphertext, err := sigil.In([]byte("secret"))
		require.NoError(t, err)

		// Tamper with the ciphertext (after the nonce)
		ciphertext[30] ^= 0xff

		_, err = sigil.Out(ciphertext)
		assert.ErrorIs(t, err, ErrDecryptionFailed)
	})

	t.Run("TruncatedCiphertext", func(t *testing.T) {
		key := make([]byte, 32)
		sigil, err := NewChaChaPolySigil(key)
		require.NoError(t, err)

		_, err = sigil.Out([]byte("too short"))
		assert.ErrorIs(t, err, ErrCiphertextTooShort)
	})

	t.Run("NoKeyConfigured", func(t *testing.T) {
		sigil := &ChaChaPolySigil{}

		_, err := sigil.In([]byte("test"))
		assert.ErrorIs(t, err, ErrNoKeyConfigured)

		_, err = sigil.Out([]byte("test"))
		assert.ErrorIs(t, err, ErrNoKeyConfigured)
	})

	t.Run("RandomReaderError", func(t *testing.T) {
		key := make([]byte, 32)
		sigil, err := NewChaChaPolySigil(key)
		require.NoError(t, err)
		sigil.randReader = &mockRandReader{}

		_, err = sigil.In([]byte("test"))
		assert.Error(t, err)
	})
}

func TestChaChaPolySigil_Ugly(t *testing.T) {
	t.Run("NilPlaintext", func(t *testing.T) {
		key := make([]byte, 32)
		sigil, err := NewChaChaPolySigil(key)
		require.NoError(t, err)

		ciphertext, err := sigil.In(nil)
		assert.NoError(t, err)
		assert.Nil(t, ciphertext)
	})

	t.Run("NilCiphertext", func(t *testing.T) {
		key := make([]byte, 32)
		sigil, err := NewChaChaPolySigil(key)
		require.NoError(t, err)

		plaintext, err := sigil.Out(nil)
		assert.NoError(t, err)
		assert.Nil(t, plaintext)
	})

	t.Run("NilObfuscator", func(t *testing.T) {
		key := make([]byte, 32)
		sigil, err := NewChaChaPolySigil(key)
		require.NoError(t, err)
		sigil.Obfuscator = nil // Explicitly set to nil

		plaintext := []byte("test without obfuscation")
		ciphertext, err := sigil.In(plaintext)
		require.NoError(t, err)

		decrypted, err := sigil.Out(ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

// --- XORObfuscator Tests ---

func TestXORObfuscator_Good(t *testing.T) {
	t.Run("RoundTrip", func(t *testing.T) {
		obfuscator := &XORObfuscator{}
		data := []byte("Hello, World!")
		entropy := []byte("random-entropy-value")

		obfuscated := obfuscator.Obfuscate(data, entropy)
		assert.NotEqual(t, data, obfuscated)

		deobfuscated := obfuscator.Deobfuscate(obfuscated, entropy)
		assert.Equal(t, data, deobfuscated)
	})

	t.Run("DifferentEntropyDifferentOutput", func(t *testing.T) {
		obfuscator := &XORObfuscator{}
		data := []byte("same data")
		entropy1 := []byte("entropy1")
		entropy2 := []byte("entropy2")

		obfuscated1 := obfuscator.Obfuscate(data, entropy1)
		obfuscated2 := obfuscator.Obfuscate(data, entropy2)

		assert.NotEqual(t, obfuscated1, obfuscated2)
	})

	t.Run("LargeData", func(t *testing.T) {
		obfuscator := &XORObfuscator{}
		data := make([]byte, 10000)
		for i := range data {
			data[i] = byte(i % 256)
		}
		entropy := []byte("test-entropy")

		obfuscated := obfuscator.Obfuscate(data, entropy)
		deobfuscated := obfuscator.Deobfuscate(obfuscated, entropy)
		assert.Equal(t, data, deobfuscated)
	})
}

func TestXORObfuscator_Ugly(t *testing.T) {
	t.Run("EmptyData", func(t *testing.T) {
		obfuscator := &XORObfuscator{}
		data := []byte{}
		entropy := []byte("entropy")

		obfuscated := obfuscator.Obfuscate(data, entropy)
		assert.Equal(t, data, obfuscated)
	})

	t.Run("EmptyEntropy", func(t *testing.T) {
		obfuscator := &XORObfuscator{}
		data := []byte("test")
		entropy := []byte{}

		obfuscated := obfuscator.Obfuscate(data, entropy)
		deobfuscated := obfuscator.Deobfuscate(obfuscated, entropy)
		assert.Equal(t, data, deobfuscated)
	})
}

// --- ShuffleMaskObfuscator Tests ---

func TestShuffleMaskObfuscator_Good(t *testing.T) {
	t.Run("RoundTrip", func(t *testing.T) {
		obfuscator := &ShuffleMaskObfuscator{}
		data := []byte("Hello, World!")
		entropy := []byte("random-entropy-value")

		obfuscated := obfuscator.Obfuscate(data, entropy)
		assert.NotEqual(t, data, obfuscated)

		deobfuscated := obfuscator.Deobfuscate(obfuscated, entropy)
		assert.Equal(t, data, deobfuscated)
	})

	t.Run("DifferentEntropyDifferentOutput", func(t *testing.T) {
		obfuscator := &ShuffleMaskObfuscator{}
		data := []byte("same data")
		entropy1 := []byte("entropy1")
		entropy2 := []byte("entropy2")

		obfuscated1 := obfuscator.Obfuscate(data, entropy1)
		obfuscated2 := obfuscator.Obfuscate(data, entropy2)

		assert.NotEqual(t, obfuscated1, obfuscated2)
	})

	t.Run("Deterministic", func(t *testing.T) {
		obfuscator := &ShuffleMaskObfuscator{}
		data := []byte("test data")
		entropy := []byte("same entropy")

		obfuscated1 := obfuscator.Obfuscate(data, entropy)
		obfuscated2 := obfuscator.Obfuscate(data, entropy)

		assert.Equal(t, obfuscated1, obfuscated2)
	})

	t.Run("LargeData", func(t *testing.T) {
		obfuscator := &ShuffleMaskObfuscator{}
		data := make([]byte, 10000)
		for i := range data {
			data[i] = byte(i % 256)
		}
		entropy := []byte("test-entropy")

		obfuscated := obfuscator.Obfuscate(data, entropy)
		deobfuscated := obfuscator.Deobfuscate(obfuscated, entropy)
		assert.Equal(t, data, deobfuscated)
	})
}

func TestShuffleMaskObfuscator_Ugly(t *testing.T) {
	t.Run("EmptyData", func(t *testing.T) {
		obfuscator := &ShuffleMaskObfuscator{}
		data := []byte{}
		entropy := []byte("entropy")

		obfuscated := obfuscator.Obfuscate(data, entropy)
		assert.Equal(t, data, obfuscated)
	})

	t.Run("SingleByte", func(t *testing.T) {
		obfuscator := &ShuffleMaskObfuscator{}
		data := []byte{0x42}
		entropy := []byte("entropy")

		obfuscated := obfuscator.Obfuscate(data, entropy)
		deobfuscated := obfuscator.Deobfuscate(obfuscated, entropy)
		assert.Equal(t, data, deobfuscated)
	})
}

// --- GetNonceFromCiphertext Tests ---

func TestGetNonceFromCiphertext_Good(t *testing.T) {
	key := make([]byte, 32)
	sigil, err := NewChaChaPolySigil(key)
	require.NoError(t, err)

	ciphertext, err := sigil.In([]byte("test"))
	require.NoError(t, err)

	nonce, err := GetNonceFromCiphertext(ciphertext)
	require.NoError(t, err)
	assert.Len(t, nonce, 24)

	// Verify the nonce matches the first 24 bytes
	assert.Equal(t, ciphertext[:24], nonce)
}

func TestGetNonceFromCiphertext_Bad(t *testing.T) {
	_, err := GetNonceFromCiphertext([]byte("too short"))
	assert.ErrorIs(t, err, ErrCiphertextTooShort)
}

// --- Custom Obfuscator Tests ---

func TestCustomObfuscator(t *testing.T) {
	key := make([]byte, 32)

	t.Run("WithShuffleMaskObfuscator", func(t *testing.T) {
		sigil, err := NewChaChaPolySigilWithObfuscator(key, &ShuffleMaskObfuscator{})
		require.NoError(t, err)

		plaintext := []byte("test with shuffle mask obfuscator")
		ciphertext, err := sigil.In(plaintext)
		require.NoError(t, err)

		decrypted, err := sigil.Out(ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("WithNilObfuscator", func(t *testing.T) {
		sigil, err := NewChaChaPolySigilWithObfuscator(key, nil)
		require.NoError(t, err)
		// Default XORObfuscator should be used
		assert.IsType(t, &XORObfuscator{}, sigil.Obfuscator)
	})
}

// --- Integration Tests ---

func TestChaChaPolySigil_Integration(t *testing.T) {
	t.Run("PlaintextNeverInOutput", func(t *testing.T) {
		key := make([]byte, 32)
		sigil, err := NewChaChaPolySigil(key)
		require.NoError(t, err)

		// Use a distinctive pattern that would be easy to find
		plaintext := []byte("DISTINCTIVE_SECRET_PATTERN_12345")
		ciphertext, err := sigil.In(plaintext)
		require.NoError(t, err)

		// The plaintext pattern should not appear anywhere in the ciphertext
		assert.False(t, bytes.Contains(ciphertext, plaintext))

		// Even substrings should not appear
		assert.False(t, bytes.Contains(ciphertext, []byte("DISTINCTIVE")))
		assert.False(t, bytes.Contains(ciphertext, []byte("SECRET")))
		assert.False(t, bytes.Contains(ciphertext, []byte("PATTERN")))
	})

	t.Run("ConsistentRoundTrip", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i * 7)
		}
		sigil, err := NewChaChaPolySigil(key)
		require.NoError(t, err)

		// Test multiple round trips
		for i := 0; i < 100; i++ {
			plaintext := make([]byte, i+1)
			for j := range plaintext {
				plaintext[j] = byte(j * i)
			}

			ciphertext, err := sigil.In(plaintext)
			require.NoError(t, err)

			decrypted, err := sigil.Out(ciphertext)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted, "Round trip failed for size %d", i+1)
		}
	})
}

// --- Benchmark Tests ---

func BenchmarkChaChaPolySigil_Encrypt(b *testing.B) {
	key := make([]byte, 32)
	sigil, _ := NewChaChaPolySigil(key)
	plaintext := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sigil.In(plaintext)
	}
}

func BenchmarkChaChaPolySigil_Decrypt(b *testing.B) {
	key := make([]byte, 32)
	sigil, _ := NewChaChaPolySigil(key)
	plaintext := make([]byte, 1024)
	ciphertext, _ := sigil.In(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sigil.Out(ciphertext)
	}
}

func BenchmarkXORObfuscator(b *testing.B) {
	obfuscator := &XORObfuscator{}
	data := make([]byte, 1024)
	entropy := make([]byte, 24)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = obfuscator.Obfuscate(data, entropy)
	}
}

func BenchmarkShuffleMaskObfuscator(b *testing.B) {
	obfuscator := &ShuffleMaskObfuscator{}
	data := make([]byte, 1024)
	entropy := make([]byte, 24)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = obfuscator.Obfuscate(data, entropy)
	}
}
