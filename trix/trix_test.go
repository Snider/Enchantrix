package trix

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeDecode(t *testing.T) {
	trix := &Trix{
		MagicNumber: [4]byte{'T', 'R', 'I', 'X'},
		Version:     1,
		Algorithm:   1,
		Nonce:       [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24},
		Ciphertext:  []byte("Hello, world!"),
	}

	encoded, err := Encode(trix)
	assert.NoError(t, err)

	decoded, err := Decode(encoded)
	assert.NoError(t, err)

	assert.Equal(t, trix.MagicNumber, decoded.MagicNumber)
	assert.Equal(t, trix.Version, decoded.Version)
	assert.Equal(t, trix.Algorithm, decoded.Algorithm)
	assert.Equal(t, trix.Nonce, decoded.Nonce)
	assert.True(t, bytes.Equal(trix.Ciphertext, decoded.Ciphertext))
}
