package rootfs

import "io/fs"

// Storage defines the interface for a passthrough storage system.
type Storage interface {
	// Read reads the data for the given key.
	Read(key string) ([]byte, error)
	// Write writes the data for the given key.
	Write(key string, data []byte) error
	// Delete deletes the data for the given key.
	Delete(key string) error
	// List lists the keys in the storage.
	List(prefix string) ([]fs.FileInfo, error)
}
