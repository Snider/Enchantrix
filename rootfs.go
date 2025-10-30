package crypt

import "github.com/Snider/Enchantrix/rootfs"

// Storage is an alias for the rootfs.Storage interface.
type Storage = rootfs.Storage

// NewRootFS creates a new encrypted passthrough storage system.
func NewRootFS(root string, key []byte) Storage {
	return rootfs.NewLocalStorage(root, key)
}
