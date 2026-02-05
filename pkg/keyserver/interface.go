// Package keyserver provides a Secure Environment (SE) service that performs
// cryptographic operations by key reference. Callers never see raw key material;
// they pass a key ID and the server performs the operation internally.
package keyserver

import (
	"context"

	"github.com/Snider/Enchantrix/pkg/keystore"
)

// KeyServer defines the interface for a key management and crypto operations
// service. All operations reference keys by ID — raw key material never leaves
// the server boundary.
type KeyServer interface {
	// --- Key lifecycle ---

	// GenerateKey creates a new random key of the specified type and stores it.
	// Returns the key ID for future reference.
	GenerateKey(ctx context.Context, keyType keystore.KeyType, label string) (keyID string, err error)

	// ImportPassword derives a symmetric key from a password (SHA-256, matching
	// Borg's DeriveKey) and stores the derived key. The raw password is never
	// persisted.
	ImportPassword(ctx context.Context, password string, label string) (keyID string, err error)

	// DeleteKey removes a key from the store and zeroes its material.
	DeleteKey(ctx context.Context, keyID string) error

	// ListKeys returns metadata for all stored keys. KeyData is never included.
	ListKeys(ctx context.Context) ([]keystore.Entry, error)

	// GetPublicKey returns the public component of an asymmetric key.
	// Returns an error for symmetric key types.
	GetPublicKey(ctx context.Context, keyID string) ([]byte, error)

	// --- Primitive crypto operations ---

	// Encrypt encrypts plaintext using the key identified by keyID.
	Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext using the key identified by keyID.
	Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)

	// Sign signs data using the key identified by keyID (HMAC for symmetric keys).
	Sign(ctx context.Context, keyID string, data []byte) ([]byte, error)

	// Verify verifies a signature against data using the key identified by keyID.
	Verify(ctx context.Context, keyID string, data, signature []byte) error

	// --- TIM composite operations (Borg calls these) ---

	// EncryptTIM encrypts a TIM's config and rootfs atomically with the same key.
	// The key never leaves the server boundary.
	EncryptTIM(ctx context.Context, keyID string, config []byte, rootfs []byte) ([]byte, error)

	// DecryptTIM decrypts a TIM payload back into config and rootfs.
	DecryptTIM(ctx context.Context, keyID string, payload []byte) (config []byte, rootfs []byte, err error)

	// --- SMSG composite operations ---

	// EncryptSMSG encrypts a message payload using the key identified by keyID.
	EncryptSMSG(ctx context.Context, keyID string, message []byte) ([]byte, error)

	// DecryptSMSG decrypts a message payload using the key identified by keyID.
	DecryptSMSG(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)

	// --- Stream key derivation (for SMSG V3) ---

	// DeriveStreamKey derives a stream key from license+date+fingerprint and
	// stores it temporarily. Returns the key ID.
	DeriveStreamKey(ctx context.Context, license, date, fingerprint string) (keyID string, err error)

	// WrapCEK wraps a Content Encryption Key with the stream key identified
	// by streamKeyID. Returns a base64-encoded wrapped key.
	WrapCEK(ctx context.Context, streamKeyID string, cek []byte) (string, error)

	// UnwrapCEK unwraps a Content Encryption Key using the stream key.
	// Takes base64-encoded wrapped key, returns raw CEK bytes.
	UnwrapCEK(ctx context.Context, streamKeyID string, wrapped string) ([]byte, error)

	// --- STMF composite operations ---

	// DecryptSTMF performs ECDH with the server's private key and the ephemeral
	// public key embedded in the STMF payload, then decrypts the form data.
	DecryptSTMF(ctx context.Context, keyID string, stmfPayload []byte) ([]byte, error)
}
