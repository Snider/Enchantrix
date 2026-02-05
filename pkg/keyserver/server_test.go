package keyserver

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/Snider/Enchantrix/pkg/enchantrix"
	"github.com/Snider/Enchantrix/pkg/keystore"
	"github.com/Snider/Enchantrix/pkg/trix"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.trix")
	store, err := keystore.Create(path, "test-master")
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	return NewServer(store)
}

func TestGenerateKeyAndList(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	id, err := srv.GenerateKey(ctx, keystore.ChaCha256, "test-key")
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	keys, err := srv.ListKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Equal(t, "test-key", keys[0].Label)
	assert.Nil(t, keys[0].KeyData, "ListKeys must not expose key data")
}

func TestImportPasswordAndDelete(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	id, err := srv.ImportPassword(ctx, "my-password", "imported")
	require.NoError(t, err)

	keys, _ := srv.ListKeys(ctx)
	assert.Len(t, keys, 1)

	err = srv.DeleteKey(ctx, id)
	require.NoError(t, err)

	keys, _ = srv.ListKeys(ctx)
	assert.Len(t, keys, 0)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	id, err := srv.GenerateKey(ctx, keystore.ChaCha256, "enc-key")
	require.NoError(t, err)

	plaintext := []byte("Hello, Secure Environment!")

	ciphertext, err := srv.Encrypt(ctx, id, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := srv.Decrypt(ctx, id, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestSignVerify(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	id, err := srv.GenerateKey(ctx, keystore.HMAC, "sign-key")
	require.NoError(t, err)

	data := []byte("sign this data")

	sig, err := srv.Sign(ctx, id, data)
	require.NoError(t, err)
	assert.Len(t, sig, 32) // HMAC-SHA256

	err = srv.Verify(ctx, id, data, sig)
	assert.NoError(t, err)

	// Tampered data should fail
	err = srv.Verify(ctx, id, []byte("tampered"), sig)
	assert.Error(t, err)
}

func TestTIMRoundTrip(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	id, err := srv.ImportPassword(ctx, "tim-password", "tim-key")
	require.NoError(t, err)

	config := []byte(`{"ociVersion":"1.0.2"}`)
	rootfs := []byte("rootfs-tar-data-here")

	// Encrypt
	payload, err := srv.EncryptTIM(ctx, id, config, rootfs)
	require.NoError(t, err)
	assert.NotEmpty(t, payload)

	// Decrypt
	decConfig, decRootFS, err := srv.DecryptTIM(ctx, id, payload)
	require.NoError(t, err)
	assert.Equal(t, config, decConfig)
	assert.Equal(t, rootfs, decRootFS)
}

func TestTIMRoundTripMatchesBorgFormat(t *testing.T) {
	// Verify our TIM payload format matches Borg's:
	// [4-byte config_size][encrypted_config][encrypted_rootfs]
	ctx := context.Background()
	srv := newTestServer(t)

	id, err := srv.ImportPassword(ctx, "test-pass", "borg-compat")
	require.NoError(t, err)

	config := []byte(`{"test":"config"}`)
	rootfs := []byte("rootfs-data")

	payload, err := srv.EncryptTIM(ctx, id, config, rootfs)
	require.NoError(t, err)

	// Verify we can also decrypt with raw Enchantrix sigil using the same key
	key := sha256.Sum256([]byte("test-pass"))
	sigil, err := enchantrix.NewChaChaPolySigil(key[:])
	require.NoError(t, err)

	// Parse payload structure
	require.True(t, len(payload) >= 4)
	configSize := uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
	encConfig := payload[4 : 4+configSize]
	encRootFS := payload[4+configSize:]

	decConfig, err := sigil.Out(encConfig)
	require.NoError(t, err)
	assert.Equal(t, config, decConfig)

	decRootFS, err := sigil.Out(encRootFS)
	require.NoError(t, err)
	assert.Equal(t, rootfs, decRootFS)
}

func TestSMSGRoundTrip(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	id, err := srv.ImportPassword(ctx, "smsg-password", "smsg-key")
	require.NoError(t, err)

	message := []byte(`{"body":"Hello, encrypted world!","timestamp":1234567890}`)

	enc, err := srv.EncryptSMSG(ctx, id, message)
	require.NoError(t, err)

	dec, err := srv.DecryptSMSG(ctx, id, enc)
	require.NoError(t, err)
	assert.Equal(t, message, dec)
}

func TestStreamKeyDerivation(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	keyID, err := srv.DeriveStreamKey(ctx, "license-123", "2025-01-15", "device-fp")
	require.NoError(t, err)
	assert.NotEmpty(t, keyID)

	// Generate a CEK and wrap/unwrap it
	cek := make([]byte, 32)
	rand.Read(cek)

	wrapped, err := srv.WrapCEK(ctx, keyID, cek)
	require.NoError(t, err)
	assert.NotEmpty(t, wrapped)

	unwrapped, err := srv.UnwrapCEK(ctx, keyID, wrapped)
	require.NoError(t, err)
	assert.Equal(t, cek, unwrapped)
}

func TestGetPublicKey(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	// Generate X25519 key
	id, err := srv.GenerateKey(ctx, keystore.X25519, "x25519-key")
	require.NoError(t, err)

	pubKey, err := srv.GetPublicKey(ctx, id)
	require.NoError(t, err)
	assert.Len(t, pubKey, 32)

	// Symmetric key should fail
	symID, err := srv.GenerateKey(ctx, keystore.ChaCha256, "sym-key")
	require.NoError(t, err)

	_, err = srv.GetPublicKey(ctx, symID)
	assert.Error(t, err)
}

func TestDecryptSTMF(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	// Generate server keypair via keyserver
	keyID, err := srv.GenerateKey(ctx, keystore.X25519, "stmf-server")
	require.NoError(t, err)

	serverPubKey, err := srv.GetPublicKey(ctx, keyID)
	require.NoError(t, err)

	// Client-side: encrypt form data using server's public key
	serverPub, err := ecdh.X25519().NewPublicKey(serverPubKey)
	require.NoError(t, err)

	ephemeralPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	sharedSecret, err := ephemeralPriv.ECDH(serverPub)
	require.NoError(t, err)

	symmetricKey := sha256.Sum256(sharedSecret)
	sigil, err := enchantrix.NewChaChaPolySigil(symmetricKey[:])
	require.NoError(t, err)

	formData := map[string]interface{}{
		"fields": []map[string]string{
			{"name": "username", "value": "alice", "type": "text"},
			{"name": "password", "value": "secret123", "type": "password"},
		},
	}
	payload, err := json.Marshal(formData)
	require.NoError(t, err)

	encrypted, err := sigil.In(payload)
	require.NoError(t, err)

	// Build STMF container
	header := map[string]interface{}{
		"version":      "1.0",
		"algorithm":    "x25519-chacha20poly1305",
		"ephemeral_pk": base64.StdEncoding.EncodeToString(ephemeralPriv.PublicKey().Bytes()),
	}

	container := &trix.Trix{
		Header:  header,
		Payload: encrypted,
	}

	stmfData, err := trix.Encode(container, "STMF", nil)
	require.NoError(t, err)

	// Server-side: decrypt via keyserver (private key never leaves)
	decrypted, err := srv.DecryptSTMF(ctx, keyID, stmfData)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(decrypted, &result)
	require.NoError(t, err)

	fields := result["fields"].([]interface{})
	first := fields[0].(map[string]interface{})
	assert.Equal(t, "username", first["name"])
	assert.Equal(t, "alice", first["value"])
}

func TestDecryptWrongKey(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	id1, _ := srv.GenerateKey(ctx, keystore.ChaCha256, "key1")
	id2, _ := srv.GenerateKey(ctx, keystore.ChaCha256, "key2")

	enc, err := srv.Encrypt(ctx, id1, []byte("secret"))
	require.NoError(t, err)

	_, err = srv.Decrypt(ctx, id2, enc)
	assert.Error(t, err)
}

func TestDeleteNonExistent(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	err := srv.DeleteKey(ctx, "nonexistent")
	assert.Error(t, err)
}

func TestEncryptWithNonExistentKey(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	_, err := srv.Encrypt(ctx, "nonexistent", []byte("data"))
	assert.Error(t, err)
}
