// Package keystore provides a Trix-based encrypted key store for managing
// cryptographic keys at rest. Keys are encrypted individually within a Trix
// container using Argon2id-derived master key material.
package keystore

import "errors"

// KeyType identifies the type of cryptographic key stored in an entry.
type KeyType string

const (
	// ChaCha256 is a 256-bit symmetric key for ChaCha20-Poly1305 encryption.
	ChaCha256 KeyType = "chacha256"
	// X25519 is an X25519 keypair for Diffie-Hellman key exchange.
	X25519 KeyType = "x25519"
	// PGP is an OpenPGP key (public, private, or both).
	PGP KeyType = "pgp"
	// HMAC is a key for HMAC-based message authentication.
	HMAC KeyType = "hmac"
)

var (
	// ErrKeyNotFound is returned when a key ID does not exist in the store.
	ErrKeyNotFound = errors.New("keystore: key not found")
	// ErrDuplicateKey is returned when a key ID already exists.
	ErrDuplicateKey = errors.New("keystore: key already exists")
	// ErrStoreClosed is returned when operating on a closed store.
	ErrStoreClosed = errors.New("keystore: store is closed")
	// ErrInvalidKeyType is returned when an unsupported key type is specified.
	ErrInvalidKeyType = errors.New("keystore: invalid key type")
	// ErrInvalidKeySize is returned when key material has an invalid size for its type.
	ErrInvalidKeySize = errors.New("keystore: invalid key size")
	// ErrDecryptionFailed is returned when the master password is incorrect.
	ErrDecryptionFailed = errors.New("keystore: decryption failed (wrong password?)")
)

// ValidKeyTypes returns all supported key types.
func ValidKeyTypes() []KeyType {
	return []KeyType{ChaCha256, X25519, PGP, HMAC}
}

// IsValid reports whether the key type is a recognized type.
func (kt KeyType) IsValid() bool {
	switch kt {
	case ChaCha256, X25519, PGP, HMAC:
		return true
	}
	return false
}

// KeySize returns the expected raw key size in bytes for the type,
// or 0 if the type has variable-length keys (e.g. PGP).
func (kt KeyType) KeySize() int {
	switch kt {
	case ChaCha256:
		return 32
	case X25519:
		return 32 // private key; public is also 32 bytes
	case HMAC:
		return 32
	default:
		return 0
	}
}
