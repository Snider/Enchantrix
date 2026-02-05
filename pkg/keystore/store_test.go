package keystore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAndOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.trix")

	// Create a new store
	store, err := Create(path, "master-password")
	require.NoError(t, err)
	require.NotNil(t, store)

	// Put a key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	err = store.Put("test-key", ChaCha256, key)
	require.NoError(t, err)

	// Save and close
	err = store.Save()
	require.NoError(t, err)
	err = store.Close()
	require.NoError(t, err)

	// Reopen
	store2, err := Open(path, "master-password")
	require.NoError(t, err)
	require.NotNil(t, store2)

	// Verify key round-trips
	entry, err := store2.Get("test-key")
	require.NoError(t, err)
	assert.Equal(t, "test-key", entry.ID)
	assert.Equal(t, ChaCha256, entry.Type)
	assert.Equal(t, key, entry.KeyData)

	store2.Close()
}

func TestOpenWrongPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.trix")

	store, err := Create(path, "correct-password")
	require.NoError(t, err)
	store.Close()

	_, err = Open(path, "wrong-password")
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestCreateExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.trix")

	store, err := Create(path, "password")
	require.NoError(t, err)
	store.Close()

	_, err = Create(path, "password")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestPutAndGet(t *testing.T) {
	store := newMemStore(t)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	err := store.Put("key1", ChaCha256, key)
	require.NoError(t, err)

	entry, err := store.Get("key1")
	require.NoError(t, err)
	assert.Equal(t, "key1", entry.ID)
	assert.Equal(t, ChaCha256, entry.Type)
	assert.Equal(t, key, entry.KeyData)
}

func TestPutDuplicate(t *testing.T) {
	store := newMemStore(t)

	key := make([]byte, 32)
	err := store.Put("key1", ChaCha256, key)
	require.NoError(t, err)

	err = store.Put("key1", ChaCha256, key)
	assert.ErrorIs(t, err, ErrDuplicateKey)
}

func TestPutInvalidKeyType(t *testing.T) {
	store := newMemStore(t)

	key := make([]byte, 32)
	err := store.Put("key1", KeyType("invalid"), key)
	assert.ErrorIs(t, err, ErrInvalidKeyType)
}

func TestPutInvalidKeySize(t *testing.T) {
	store := newMemStore(t)

	// ChaCha256 requires 32 bytes
	key := make([]byte, 16)
	err := store.Put("key1", ChaCha256, key)
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}

func TestGetNotFound(t *testing.T) {
	store := newMemStore(t)

	_, err := store.Get("nonexistent")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestGetReturnsClone(t *testing.T) {
	store := newMemStore(t)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	store.Put("key1", ChaCha256, key)

	entry, _ := store.Get("key1")
	// Mutate the clone
	entry.KeyData[0] = 0xFF

	// Original should be unchanged
	entry2, _ := store.Get("key1")
	assert.Equal(t, byte(0), entry2.KeyData[0])
}

func TestDelete(t *testing.T) {
	store := newMemStore(t)

	key := make([]byte, 32)
	store.Put("key1", ChaCha256, key)

	err := store.Delete("key1")
	require.NoError(t, err)

	_, err = store.Get("key1")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestDeleteNotFound(t *testing.T) {
	store := newMemStore(t)

	err := store.Delete("nonexistent")
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestList(t *testing.T) {
	store := newMemStore(t)

	key := make([]byte, 32)
	store.Put("key1", ChaCha256, key)
	store.Put("key2", ChaCha256, key)

	list := store.List()
	assert.Len(t, list, 2)

	// Verify no key data exposed
	for _, entry := range list {
		assert.Nil(t, entry.KeyData, "List() must not expose key data")
	}
}

func TestListEmpty(t *testing.T) {
	store := newMemStore(t)
	list := store.List()
	assert.Empty(t, list)
}

func TestImport(t *testing.T) {
	store := newMemStore(t)

	id, err := store.Import("my-password", "test-import")
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	entry, err := store.Get(id)
	require.NoError(t, err)
	assert.Equal(t, ChaCha256, entry.Type)
	assert.Equal(t, "test-import", entry.Label)
	assert.Len(t, entry.KeyData, 32)
	assert.Equal(t, "password", entry.Metadata["derived_from"])

	// Importing the same password again should produce the same key data
	id2, err := store.Import("my-password", "test-import-2")
	require.NoError(t, err)

	entry2, _ := store.Get(id2)
	assert.Equal(t, entry.KeyData, entry2.KeyData, "same password should derive same key")
}

func TestGenerate(t *testing.T) {
	t.Run("ChaCha256", func(t *testing.T) {
		store := newMemStore(t)

		id, err := store.Generate(ChaCha256, "gen-chacha")
		require.NoError(t, err)

		entry, err := store.Get(id)
		require.NoError(t, err)
		assert.Equal(t, ChaCha256, entry.Type)
		assert.Equal(t, "gen-chacha", entry.Label)
		assert.Len(t, entry.KeyData, 32)
		assert.Equal(t, "true", entry.Metadata["generated"])
	})

	t.Run("X25519", func(t *testing.T) {
		store := newMemStore(t)

		id, err := store.Generate(X25519, "gen-x25519")
		require.NoError(t, err)

		entry, err := store.Get(id)
		require.NoError(t, err)
		assert.Equal(t, X25519, entry.Type)
		assert.Len(t, entry.KeyData, 32)
		assert.NotEmpty(t, entry.Metadata["public_key"])
	})

	t.Run("HMAC", func(t *testing.T) {
		store := newMemStore(t)

		id, err := store.Generate(HMAC, "gen-hmac")
		require.NoError(t, err)

		entry, err := store.Get(id)
		require.NoError(t, err)
		assert.Equal(t, HMAC, entry.Type)
		assert.Len(t, entry.KeyData, 32)
	})

	t.Run("InvalidType", func(t *testing.T) {
		store := newMemStore(t)

		_, err := store.Generate(KeyType("bogus"), "")
		assert.ErrorIs(t, err, ErrInvalidKeyType)
	})
}

func TestClosedStore(t *testing.T) {
	store := newMemStore(t)
	store.Close()

	key := make([]byte, 32)

	_, err := store.Get("key1")
	assert.ErrorIs(t, err, ErrStoreClosed)

	err = store.Put("key1", ChaCha256, key)
	assert.ErrorIs(t, err, ErrStoreClosed)

	err = store.Delete("key1")
	assert.ErrorIs(t, err, ErrStoreClosed)

	err = store.Save()
	assert.ErrorIs(t, err, ErrStoreClosed)
}

func TestCloseZeroesKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.trix")

	store, err := Create(path, "password")
	require.NoError(t, err)

	key := make([]byte, 32)
	for i := range key {
		key[i] = 0xFF
	}
	store.Put("key1", ChaCha256, key)

	// Keep reference to master key and entry key
	masterRef := store.master

	store.Close()

	// Master key should be zeroed
	for _, b := range masterRef {
		assert.Equal(t, byte(0), b, "master key not zeroed after Close")
	}
}

func TestRoundTripPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.trix")

	// Create, add multiple keys, save
	store, err := Create(path, "test-password-123")
	require.NoError(t, err)

	key1 := make([]byte, 32)
	for i := range key1 {
		key1[i] = byte(i)
	}
	store.Put("sym-key", ChaCha256, key1)

	id, err := store.Generate(X25519, "my-x25519")
	require.NoError(t, err)

	importID, err := store.Import("user-password", "imported")
	require.NoError(t, err)

	store.Save()

	// Read back the x25519 entry before closing
	x25519Entry, _ := store.Get(id)
	importEntry, _ := store.Get(importID)

	store.Close()

	// Reopen and verify all entries
	store2, err := Open(path, "test-password-123")
	require.NoError(t, err)

	// Verify symmetric key
	entry1, err := store2.Get("sym-key")
	require.NoError(t, err)
	assert.Equal(t, key1, entry1.KeyData)
	assert.Equal(t, ChaCha256, entry1.Type)

	// Verify X25519 key
	entry2, err := store2.Get(id)
	require.NoError(t, err)
	assert.Equal(t, x25519Entry.KeyData, entry2.KeyData)
	assert.Equal(t, X25519, entry2.Type)

	// Verify imported key
	entry3, err := store2.Get(importID)
	require.NoError(t, err)
	assert.Equal(t, importEntry.KeyData, entry3.KeyData)

	// Verify list count
	list := store2.List()
	assert.Len(t, list, 3)

	store2.Close()
}

func TestSaveAfterDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.trix")

	store, err := Create(path, "password")
	require.NoError(t, err)

	key := make([]byte, 32)
	store.Put("key1", ChaCha256, key)
	store.Put("key2", ChaCha256, key)
	store.Save()
	store.Close()

	store2, err := Open(path, "password")
	require.NoError(t, err)
	store2.Delete("key1")
	store2.Save()
	store2.Close()

	store3, err := Open(path, "password")
	require.NoError(t, err)
	_, err = store3.Get("key1")
	assert.ErrorIs(t, err, ErrKeyNotFound)

	entry, err := store3.Get("key2")
	require.NoError(t, err)
	assert.Equal(t, "key2", entry.ID)
	store3.Close()
}

func TestOpenNonExistentFile(t *testing.T) {
	_, err := Open("/nonexistent/path/store.trix", "password")
	assert.Error(t, err)
}

func TestAtomicSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.trix")

	store, err := Create(path, "password")
	require.NoError(t, err)

	key := make([]byte, 32)
	store.Put("key1", ChaCha256, key)
	store.Save()

	// Verify no temp file left behind
	_, err = os.Stat(path + ".tmp")
	assert.True(t, os.IsNotExist(err), "temp file should not exist after save")

	store.Close()
}

func TestPutEntry(t *testing.T) {
	store := newMemStore(t)

	entry := &Entry{
		ID:      "custom-id",
		Type:    ChaCha256,
		KeyData: make([]byte, 32),
		Label:   "custom-label",
		Metadata: map[string]string{
			"purpose": "testing",
		},
	}

	err := store.PutEntry(entry)
	require.NoError(t, err)

	got, err := store.Get("custom-id")
	require.NoError(t, err)
	assert.Equal(t, "custom-label", got.Label)
	assert.Equal(t, "testing", got.Metadata["purpose"])
	assert.False(t, got.CreatedAt.IsZero())
}

func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.trix")

	store, err := Create(path, "password")
	require.NoError(t, err)
	store.Close()

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "store file should be 0600")
}

// newMemStore creates a temporary file-backed store for testing.
func newMemStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.trix")
	store, err := Create(path, "test-password")
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	return store
}
