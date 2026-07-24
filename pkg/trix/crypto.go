package trix

import (
	"errors"
	"time"

	"github.com/Snider/Enchantrix/pkg/enchantrix"
)

var (
	// ErrNoEncryptionKey is returned when encryption is requested without a key.
	ErrNoEncryptionKey = errors.New("trix: encryption key not configured")
	// ErrAlreadyEncrypted is returned when trying to encrypt already encrypted data.
	ErrAlreadyEncrypted = errors.New("trix: payload is already encrypted")
	// ErrNotEncrypted is returned when trying to decrypt non-encrypted data.
	ErrNotEncrypted = errors.New("trix: payload is not encrypted")
)

const (
	// HeaderKeyEncrypted indicates whether the payload is encrypted.
	HeaderKeyEncrypted = "encrypted"
	// HeaderKeyAlgorithm stores the encryption algorithm used.
	HeaderKeyAlgorithm = "encryption_algorithm"
	// HeaderKeyEncryptedAt stores when the payload was encrypted.
	HeaderKeyEncryptedAt = "encrypted_at"
	// HeaderKeyObfuscator stores the obfuscator type used.
	HeaderKeyObfuscator = "obfuscator"

	// AlgorithmChaCha20Poly1305 is the identifier for ChaCha20-Poly1305.
	AlgorithmChaCha20Poly1305 = "xchacha20-poly1305"
	// ObfuscatorXOR identifies the XOR obfuscator.
	ObfuscatorXOR = "xor"
	// ObfuscatorShuffleMask identifies the shuffle-mask obfuscator.
	ObfuscatorShuffleMask = "shuffle-mask"
)

// CryptoConfig holds encryption configuration for a Trix container.
type CryptoConfig struct {
	// Key is the 32-byte encryption key.
	Key []byte
	// Obfuscator type: "xor" (default) or "shuffle-mask"
	Obfuscator string
}

// EncryptPayload encrypts the Trix payload using ChaCha20-Poly1305 with pre-obfuscation.
//
// The nonce is embedded in the ciphertext itself and is NOT stored separately
// in the header. This is the production-ready approach (not demo-style).
//
// Header metadata is updated to indicate encryption status without exposing
// cryptographic parameters that are already embedded in the ciphertext.
func (t *Trix) EncryptPayload(config *CryptoConfig) error {
	if config == nil || len(config.Key) != 32 {
		return ErrNoEncryptionKey
	}

	// Check if already encrypted
	if encrypted, ok := t.Header[HeaderKeyEncrypted].(bool); ok && encrypted {
		return ErrAlreadyEncrypted
	}

	// Create the obfuscator
	var obfuscator enchantrix.PreObfuscator
	obfuscatorName := ObfuscatorXOR
	switch config.Obfuscator {
	case ObfuscatorShuffleMask:
		obfuscator = &enchantrix.ShuffleMaskObfuscator{}
		obfuscatorName = ObfuscatorShuffleMask
	default:
		obfuscator = &enchantrix.XORObfuscator{}
	}

	// Create the encryption sigil
	sigil, err := enchantrix.NewChaChaPolySigilWithObfuscator(config.Key, obfuscator)
	if err != nil {
		return err
	}

	// Encrypt the payload
	ciphertext, err := sigil.In(t.Payload)
	if err != nil {
		return err
	}

	// Update payload with ciphertext
	t.Payload = ciphertext

	// Update header with encryption metadata
	// NOTE: We do NOT store the nonce in the header - it's embedded in the ciphertext
	if t.Header == nil {
		t.Header = make(map[string]interface{})
	}
	t.Header[HeaderKeyEncrypted] = true
	t.Header[HeaderKeyAlgorithm] = AlgorithmChaCha20Poly1305
	t.Header[HeaderKeyObfuscator] = obfuscatorName
	t.Header[HeaderKeyEncryptedAt] = time.Now().UTC().Format(time.RFC3339)

	return nil
}

// DecryptPayload decrypts the Trix payload using the provided key.
//
// The nonce is extracted from the ciphertext itself - no need to read it
// from the header separately.
func (t *Trix) DecryptPayload(config *CryptoConfig) error {
	if config == nil || len(config.Key) != 32 {
		return ErrNoEncryptionKey
	}

	// Check if encrypted
	encrypted, ok := t.Header[HeaderKeyEncrypted].(bool)
	if !ok || !encrypted {
		return ErrNotEncrypted
	}

	// Determine obfuscator from header
	var obfuscator enchantrix.PreObfuscator
	if obfType, ok := t.Header[HeaderKeyObfuscator].(string); ok {
		switch obfType {
		case ObfuscatorShuffleMask:
			obfuscator = &enchantrix.ShuffleMaskObfuscator{}
		default:
			obfuscator = &enchantrix.XORObfuscator{}
		}
	} else {
		obfuscator = &enchantrix.XORObfuscator{}
	}

	// Create the decryption sigil
	sigil, err := enchantrix.NewChaChaPolySigilWithObfuscator(config.Key, obfuscator)
	if err != nil {
		return err
	}

	// Decrypt the payload
	plaintext, err := sigil.Out(t.Payload)
	if err != nil {
		return err
	}

	// Update payload with plaintext
	t.Payload = plaintext

	// Update header to indicate decrypted state
	t.Header[HeaderKeyEncrypted] = false

	return nil
}

// IsEncrypted returns true if the payload is currently encrypted.
func (t *Trix) IsEncrypted() bool {
	if t.Header == nil {
		return false
	}
	encrypted, ok := t.Header[HeaderKeyEncrypted].(bool)
	return ok && encrypted
}

// GetEncryptionAlgorithm returns the encryption algorithm used, if any.
func (t *Trix) GetEncryptionAlgorithm() string {
	if t.Header == nil {
		return ""
	}
	algo, ok := t.Header[HeaderKeyAlgorithm].(string)
	if !ok {
		return ""
	}
	return algo
}

// NewEncryptedTrix creates a new Trix container with an encrypted payload.
// This is a convenience function for creating encrypted containers in one step.
func NewEncryptedTrix(payload []byte, key []byte, header map[string]interface{}) (*Trix, error) {
	if header == nil {
		header = make(map[string]interface{})
	}

	t := &Trix{
		Header:  header,
		Payload: payload,
	}

	config := &CryptoConfig{Key: key}
	if err := t.EncryptPayload(config); err != nil {
		return nil, err
	}

	return t, nil
}
