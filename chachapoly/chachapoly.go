package chachapoly

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Encrypt encrypts data using ChaCha20-Poly1305.
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: got %d bytes, want %d bytes", len(key), chacha20poly1305.KeySize)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts data using ChaCha20-Poly1305.
func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: got %d bytes, want %d bytes", len(key), chacha20poly1305.KeySize)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]

	return aead.Open(nil, nonce, ciphertext, nil)
}
