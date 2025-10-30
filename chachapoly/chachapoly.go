package chachapoly

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/Snider/Enchantrix/trix"
	"golang.org/x/crypto/chacha20poly1305"
)

// Encrypt encrypts data using ChaCha20-Poly1305 and returns a .trix file format.
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: got %d bytes, want %d bytes", len(key), chacha20poly1305.KeySize)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonceBytes := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonceBytes, plaintext, nil)

	var nonce [24]byte
	copy(nonce[:], nonceBytes)

	trixData := &trix.Trix{
		MagicNumber: [4]byte{'T', 'R', 'I', 'X'},
		Version:     trix.Version,
		Algorithm:   trix.Algorithm,
		Nonce:       nonce,
		Ciphertext:  ciphertext,
	}

	return trix.Encode(trixData)
}

// Decrypt decrypts data from a .trix file format using ChaCha20-Poly1305.
func Decrypt(trixEncoded []byte, key []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: got %d bytes, want %d bytes", len(key), chacha20poly1305.KeySize)
	}

	trixData, err := trix.Decode(trixEncoded)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonceBytes := trixData.Nonce[:]
	ciphertext := trixData.Ciphertext

	return aead.Open(nil, nonceBytes, ciphertext, nil)
}
