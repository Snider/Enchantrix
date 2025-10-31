package rootfs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLocalStorage(t *testing.T) {
	// Create a temporary directory for testing.
	tempDir, err := os.MkdirTemp("", "enchantrix-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a new LocalStorage instance.
	key := make([]byte, 32)
	for i := range key {
		key[i] = 1
	}
	storage := NewLocalStorage(tempDir, key)

	// Test Write and Read.
	err = storage.Write("test.txt", []byte("hello"))
	assert.NoError(t, err)
	data, err := storage.Read("test.txt")
	assert.NoError(t, err)
	assert.Equal(t, []byte("hello"), data)

	// Test List.
	files, err := storage.List("")
	assert.NoError(t, err)
	assert.Len(t, files, 1)
	assert.Equal(t, "test.txt", files[0].Name())

	// Test Delete.
	err = storage.Delete("test.txt")
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(tempDir, "test.txt"))
	assert.True(t, os.IsNotExist(err))
}
