package keyserver

import (
	"context"
	"fmt"
	"sync"

	"github.com/Snider/Enchantrix/pkg/keystore"
)

// Server is an in-process KeyServer backed by a keystore.Store.
// It holds the store open and performs all crypto operations internally —
// callers only see key IDs and encrypted results.
type Server struct {
	store *keystore.Store
	mu    sync.RWMutex
}

// NewServer creates a new keyserver backed by the given store.
func NewServer(store *keystore.Store) *Server {
	return &Server{store: store}
}

// GenerateKey creates a new random key of the specified type.
func (s *Server) GenerateKey(ctx context.Context, keyType keystore.KeyType, label string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, err := s.store.Generate(keyType, label)
	if err != nil {
		return "", fmt.Errorf("keyserver: generate key: %w", err)
	}

	return id, nil
}

// ImportPassword derives a key from a password and stores it.
func (s *Server) ImportPassword(ctx context.Context, password string, label string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, err := s.store.Import(password, label)
	if err != nil {
		return "", fmt.Errorf("keyserver: import password: %w", err)
	}

	return id, nil
}

// DeleteKey removes a key from the store.
func (s *Server) DeleteKey(ctx context.Context, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.store.Delete(keyID); err != nil {
		return fmt.Errorf("keyserver: delete key: %w", err)
	}

	return nil
}

// ListKeys returns metadata for all keys (no key material).
func (s *Server) ListKeys(ctx context.Context) ([]keystore.Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.store.List(), nil
}

// GetPublicKey returns the public component of an asymmetric key.
func (s *Server) GetPublicKey(ctx context.Context, keyID string) ([]byte, error) {
	return s.getPublicKey(keyID)
}

// getKey retrieves the raw key material for internal use. Never exposed externally.
func (s *Server) getKey(keyID string) (*keystore.Entry, error) {
	entry, err := s.store.Get(keyID)
	if err != nil {
		return nil, fmt.Errorf("keyserver: %w", err)
	}
	return entry, nil
}

// Store returns the underlying keystore for direct access (e.g. for Save).
func (s *Server) Store() *keystore.Store {
	return s.store
}
