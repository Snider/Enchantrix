package rootfs

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Snider/Enchantrix/chachapoly"
)

// LocalStorage provides a passthrough storage system that encrypts data at rest.
type LocalStorage struct {
	root    string
	key     []byte
	filePerm fs.FileMode
	dirPerm  fs.FileMode
}

// NewLocalStorage creates a new LocalStorage.
func NewLocalStorage(root string, key []byte) *LocalStorage {
	return &LocalStorage{
		root:    root,
		key:     key,
		filePerm: 0644,
		dirPerm:  0755,
	}
}

// Read reads and decrypts the data for the given key.
func (s *LocalStorage) Read(key string) ([]byte, error) {
	path := filepath.Join(s.root, key)
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return chachapoly.Decrypt(ciphertext, s.key)
}

// Write encrypts and writes the data for the given key.
func (s *LocalStorage) Write(key string, data []byte) error {
	ciphertext, err := chachapoly.Encrypt(data, s.key)
	if err != nil {
		return err
	}
	path := filepath.Join(s.root, key)
	if err := os.MkdirAll(filepath.Dir(path), s.dirPerm); err != nil {
		return err
	}
	return os.WriteFile(path, ciphertext, s.filePerm)
}

// Delete deletes the data for the given key.
func (s *LocalStorage) Delete(key string) error {
	path := filepath.Join(s.root, key)
	return os.Remove(path)
}

// List lists the keys in the storage.
func (s *LocalStorage) List(prefix string) ([]fs.FileInfo, error) {
	var files []fs.FileInfo
	err := filepath.Walk(filepath.Join(s.root, prefix), func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, info)
		}
		return nil
	})
	return files, err
}
