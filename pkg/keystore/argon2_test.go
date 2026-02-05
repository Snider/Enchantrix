package keystore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveKey(t *testing.T) {
	t.Run("generates salt when nil", func(t *testing.T) {
		key, salt, err := DeriveKey("password", nil, nil)
		require.NoError(t, err)
		assert.Len(t, key, 32)
		assert.Len(t, salt, 16)
	})

	t.Run("uses provided salt", func(t *testing.T) {
		salt := make([]byte, 16)
		for i := range salt {
			salt[i] = byte(i)
		}

		key1, usedSalt, err := DeriveKey("password", salt, nil)
		require.NoError(t, err)
		assert.Equal(t, salt, usedSalt)

		// Same password + salt = same key
		key2, _, err := DeriveKey("password", salt, nil)
		require.NoError(t, err)
		assert.Equal(t, key1, key2)
	})

	t.Run("different passwords produce different keys", func(t *testing.T) {
		salt := make([]byte, 16)

		key1, _, err := DeriveKey("password1", salt, nil)
		require.NoError(t, err)

		key2, _, err := DeriveKey("password2", salt, nil)
		require.NoError(t, err)

		assert.NotEqual(t, key1, key2)
	})

	t.Run("different salts produce different keys", func(t *testing.T) {
		salt1 := make([]byte, 16)
		salt2 := make([]byte, 16)
		salt2[0] = 1

		key1, _, err := DeriveKey("password", salt1, nil)
		require.NoError(t, err)

		key2, _, err := DeriveKey("password", salt2, nil)
		require.NoError(t, err)

		assert.NotEqual(t, key1, key2)
	})

	t.Run("custom params", func(t *testing.T) {
		params := &Argon2Params{
			Time:    2,
			Memory:  32 * 1024,
			Threads: 2,
			KeyLen:  32,
		}

		key, _, err := DeriveKey("password", nil, params)
		require.NoError(t, err)
		assert.Len(t, key, 32)
	})
}

func TestDefaultArgon2Params(t *testing.T) {
	params := DefaultArgon2Params()
	assert.Equal(t, uint32(1), params.Time)
	assert.Equal(t, uint32(64*1024), params.Memory)
	assert.Equal(t, uint8(4), params.Threads)
	assert.Equal(t, uint32(32), params.KeyLen)
}
