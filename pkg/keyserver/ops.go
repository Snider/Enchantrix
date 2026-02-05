package keyserver

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"github.com/Snider/Enchantrix/pkg/crypt"
	"github.com/Snider/Enchantrix/pkg/enchantrix"
	"github.com/Snider/Enchantrix/pkg/keystore"
	"github.com/Snider/Enchantrix/pkg/trix"
)

func generateID() string {
	b := make([]byte, 8)
	io.ReadFull(rand.Reader, b)
	return fmt.Sprintf("%x", b)
}

// --- Primitive crypto operations ---

// Encrypt encrypts plaintext using ChaCha20-Poly1305 with the referenced key.
func (s *Server) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	entry, err := s.getKey(keyID)
	if err != nil {
		return nil, err
	}

	sigil, err := enchantrix.NewChaChaPolySigil(entry.KeyData)
	if err != nil {
		return nil, fmt.Errorf("keyserver: encrypt: %w", err)
	}

	return sigil.In(plaintext)
}

// Decrypt decrypts ciphertext using ChaCha20-Poly1305 with the referenced key.
func (s *Server) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	entry, err := s.getKey(keyID)
	if err != nil {
		return nil, err
	}

	sigil, err := enchantrix.NewChaChaPolySigil(entry.KeyData)
	if err != nil {
		return nil, fmt.Errorf("keyserver: decrypt: %w", err)
	}

	plaintext, err := sigil.Out(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("keyserver: decrypt: %w", err)
	}
	return plaintext, nil
}

// Sign produces an HMAC-SHA256 signature for symmetric keys.
func (s *Server) Sign(ctx context.Context, keyID string, data []byte) ([]byte, error) {
	entry, err := s.getKey(keyID)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, entry.KeyData)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// Verify checks an HMAC-SHA256 signature for symmetric keys.
func (s *Server) Verify(ctx context.Context, keyID string, data, signature []byte) error {
	expected, err := s.Sign(ctx, keyID, data)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, signature) {
		return fmt.Errorf("keyserver: signature verification failed")
	}
	return nil
}

// --- TIM composite operations ---

// EncryptTIM encrypts config and rootfs separately with the same key,
// matching Borg's TIM payload format:
//
//	[4-byte config_size][encrypted_config][encrypted_rootfs]
func (s *Server) EncryptTIM(ctx context.Context, keyID string, config []byte, rootfs []byte) ([]byte, error) {
	entry, err := s.getKey(keyID)
	if err != nil {
		return nil, err
	}

	sigil, err := enchantrix.NewChaChaPolySigil(entry.KeyData)
	if err != nil {
		return nil, fmt.Errorf("keyserver: encrypt TIM: %w", err)
	}

	encConfig, err := sigil.In(config)
	if err != nil {
		return nil, fmt.Errorf("keyserver: encrypt TIM config: %w", err)
	}

	encRootFS, err := sigil.In(rootfs)
	if err != nil {
		return nil, fmt.Errorf("keyserver: encrypt TIM rootfs: %w", err)
	}

	// Build payload: [config_size(4 bytes)][encrypted_config][encrypted_rootfs]
	payload := make([]byte, 4+len(encConfig)+len(encRootFS))
	binary.BigEndian.PutUint32(payload[:4], uint32(len(encConfig)))
	copy(payload[4:4+len(encConfig)], encConfig)
	copy(payload[4+len(encConfig):], encRootFS)

	return payload, nil
}

// DecryptTIM decrypts a TIM payload back into config and rootfs.
func (s *Server) DecryptTIM(ctx context.Context, keyID string, payload []byte) ([]byte, []byte, error) {
	if len(payload) < 4 {
		return nil, nil, fmt.Errorf("keyserver: decrypt TIM: payload too short")
	}

	entry, err := s.getKey(keyID)
	if err != nil {
		return nil, nil, err
	}

	sigil, err := enchantrix.NewChaChaPolySigil(entry.KeyData)
	if err != nil {
		return nil, nil, fmt.Errorf("keyserver: decrypt TIM: %w", err)
	}

	configSize := binary.BigEndian.Uint32(payload[:4])
	if len(payload) < int(4+configSize) {
		return nil, nil, fmt.Errorf("keyserver: decrypt TIM: invalid payload structure")
	}

	encConfig := payload[4 : 4+configSize]
	encRootFS := payload[4+configSize:]

	config, err := sigil.Out(encConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("keyserver: decrypt TIM config: %w", err)
	}

	rootfs, err := sigil.Out(encRootFS)
	if err != nil {
		return nil, nil, fmt.Errorf("keyserver: decrypt TIM rootfs: %w", err)
	}

	return config, rootfs, nil
}

// --- SMSG composite operations ---

// EncryptSMSG encrypts a message payload using ChaCha20-Poly1305.
func (s *Server) EncryptSMSG(ctx context.Context, keyID string, message []byte) ([]byte, error) {
	return s.Encrypt(ctx, keyID, message)
}

// DecryptSMSG decrypts a message payload using ChaCha20-Poly1305.
func (s *Server) DecryptSMSG(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	return s.Decrypt(ctx, keyID, ciphertext)
}

// --- Stream key derivation (SMSG V3) ---

// DeriveStreamKey derives a stream key from license+date+fingerprint using
// the LTHN rolling key algorithm (matching Borg's smsg.DeriveStreamKey).
// The derived key is stored and its ID returned.
func (s *Server) DeriveStreamKey(ctx context.Context, license, date, fingerprint string) (string, error) {
	input := fmt.Sprintf("%s:%s:%s", date, license, fingerprint)
	cryptService := crypt.NewService()
	lthnHash := cryptService.Hash(crypt.LTHN, input)
	key := sha256.Sum256([]byte(lthnHash))

	label := fmt.Sprintf("stream-%s-%s", license, date)
	entry := &keystore.Entry{
		ID:      generateID(),
		Type:    keystore.ChaCha256,
		KeyData: key[:],
		Label:   label,
		Metadata: map[string]string{
			"derived_from": "stream",
			"kdf":          "lthn-sha256",
			"license":      license,
			"date":         date,
			"fingerprint":  fingerprint,
		},
	}

	if err := s.store.PutEntry(entry); err != nil {
		return "", fmt.Errorf("keyserver: derive stream key: %w", err)
	}

	return entry.ID, nil
}

// WrapCEK wraps a Content Encryption Key with the stream key.
func (s *Server) WrapCEK(ctx context.Context, streamKeyID string, cek []byte) (string, error) {
	entry, err := s.getKey(streamKeyID)
	if err != nil {
		return "", err
	}

	sigil, err := enchantrix.NewChaChaPolySigil(entry.KeyData)
	if err != nil {
		return "", fmt.Errorf("keyserver: wrap CEK: %w", err)
	}

	wrapped, err := sigil.In(cek)
	if err != nil {
		return "", fmt.Errorf("keyserver: wrap CEK: %w", err)
	}

	return base64.StdEncoding.EncodeToString(wrapped), nil
}

// UnwrapCEK unwraps a Content Encryption Key using the stream key.
func (s *Server) UnwrapCEK(ctx context.Context, streamKeyID string, wrapped string) ([]byte, error) {
	entry, err := s.getKey(streamKeyID)
	if err != nil {
		return nil, err
	}

	wrappedBytes, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, fmt.Errorf("keyserver: unwrap CEK: invalid base64: %w", err)
	}

	sigil, err := enchantrix.NewChaChaPolySigil(entry.KeyData)
	if err != nil {
		return nil, fmt.Errorf("keyserver: unwrap CEK: %w", err)
	}

	cek, err := sigil.Out(wrappedBytes)
	if err != nil {
		return nil, fmt.Errorf("keyserver: unwrap CEK: decryption failed")
	}

	return cek, nil
}

// --- STMF operations ---

// getPublicKey extracts the public key from an X25519 keypair entry.
func (s *Server) getPublicKey(keyID string) ([]byte, error) {
	entry, err := s.getKey(keyID)
	if err != nil {
		return nil, err
	}

	if entry.Type != keystore.X25519 {
		return nil, fmt.Errorf("keyserver: GetPublicKey: key %s is %s, not X25519", keyID, entry.Type)
	}

	// Derive public key from private key
	privKey, err := ecdh.X25519().NewPrivateKey(entry.KeyData)
	if err != nil {
		return nil, fmt.Errorf("keyserver: GetPublicKey: %w", err)
	}

	return privKey.PublicKey().Bytes(), nil
}

// DecryptSTMF performs ECDH with the server's X25519 private key and the
// ephemeral public key from the STMF header, derives the symmetric key,
// and decrypts the form data. The private key never leaves the server.
func (s *Server) DecryptSTMF(ctx context.Context, keyID string, stmfPayload []byte) ([]byte, error) {
	entry, err := s.getKey(keyID)
	if err != nil {
		return nil, err
	}

	if entry.Type != keystore.X25519 {
		return nil, fmt.Errorf("keyserver: DecryptSTMF: key %s is %s, not X25519", keyID, entry.Type)
	}

	// Load server's private key
	serverPriv, err := ecdh.X25519().NewPrivateKey(entry.KeyData)
	if err != nil {
		return nil, fmt.Errorf("keyserver: DecryptSTMF: invalid private key: %w", err)
	}

	// Decode STMF Trix container
	t, err := trix.Decode(stmfPayload, "STMF", nil)
	if err != nil {
		return nil, fmt.Errorf("keyserver: DecryptSTMF: invalid STMF container: %w", err)
	}

	// Extract ephemeral public key from header
	ephemeralPKBase64, ok := t.Header["ephemeral_pk"].(string)
	if !ok {
		return nil, fmt.Errorf("keyserver: DecryptSTMF: missing ephemeral_pk in header")
	}

	ephemeralPKBytes, err := base64.StdEncoding.DecodeString(ephemeralPKBase64)
	if err != nil {
		return nil, fmt.Errorf("keyserver: DecryptSTMF: invalid ephemeral_pk base64: %w", err)
	}

	ephemeralPub, err := ecdh.X25519().NewPublicKey(ephemeralPKBytes)
	if err != nil {
		return nil, fmt.Errorf("keyserver: DecryptSTMF: invalid ephemeral public key: %w", err)
	}

	// ECDH: server_private × ephemeral_public = shared_secret
	sharedSecret, err := serverPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("keyserver: DecryptSTMF: ECDH failed: %w", err)
	}

	// Derive symmetric key
	symmetricKey := sha256.Sum256(sharedSecret)

	// Decrypt
	sigil, err := enchantrix.NewChaChaPolySigil(symmetricKey[:])
	if err != nil {
		return nil, fmt.Errorf("keyserver: DecryptSTMF: %w", err)
	}

	plaintext, err := sigil.Out(t.Payload)
	if err != nil {
		return nil, fmt.Errorf("keyserver: DecryptSTMF: decryption failed")
	}

	// Verify it's valid JSON (form data)
	var check json.RawMessage
	if err := json.Unmarshal(plaintext, &check); err != nil {
		return nil, fmt.Errorf("keyserver: DecryptSTMF: invalid form data JSON: %w", err)
	}

	return plaintext, nil
}
