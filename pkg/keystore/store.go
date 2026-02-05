package keystore

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/Snider/Enchantrix/pkg/enchantrix"
	"github.com/Snider/Enchantrix/pkg/trix"
)

const storeMagic = "KEYS"

// storeData is the serialized form persisted inside the Trix container.
type storeData struct {
	Salt         []byte        `json:"salt"`
	Argon2Params *Argon2Params `json:"argon2_params"`
	Entries      []*Entry      `json:"entries"`
}

// Store is an encrypted key store backed by a Trix container file.
// All key entries are encrypted at rest using a master key derived from
// the master password via Argon2id.
type Store struct {
	path    string
	master  []byte // Argon2id(masterPassword, salt)
	salt    []byte
	params  *Argon2Params
	entries map[string]*Entry
	mu      sync.RWMutex
	closed  bool
}

// Create initializes a new key store at the given path with the provided
// master password. The file must not already exist.
func Create(path string, masterPassword string) (*Store, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("keystore: file already exists: %s", path)
	}

	params := DefaultArgon2Params()
	master, salt, err := DeriveKey(masterPassword, nil, params)
	if err != nil {
		return nil, err
	}

	s := &Store{
		path:    path,
		master:  master,
		salt:    salt,
		params:  params,
		entries: make(map[string]*Entry),
	}

	if err := s.Save(); err != nil {
		return nil, err
	}

	return s, nil
}

// Open loads an existing key store from disk and decrypts it with the
// master password.
func Open(path string, masterPassword string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keystore: %w", err)
	}

	// Decode the outer Trix container (unencrypted envelope)
	container, err := trix.Decode(data, storeMagic, nil)
	if err != nil {
		return nil, fmt.Errorf("keystore: invalid store file: %w", err)
	}

	// Extract salt and params from the Trix header
	saltHex, _ := container.Header["salt"].(string)
	paramsJSON, _ := container.Header["argon2_params"].(string)

	var salt []byte
	if err := json.Unmarshal([]byte(`"`+saltHex+`"`), &salt); err != nil {
		// Try direct approach - header stores as base64 via JSON
		return nil, fmt.Errorf("keystore: invalid salt in header: %w", err)
	}

	var params Argon2Params
	if err := json.Unmarshal([]byte(paramsJSON), &params); err != nil {
		return nil, fmt.Errorf("keystore: invalid argon2 params: %w", err)
	}

	// Derive master key
	master, _, err := DeriveKey(masterPassword, salt, &params)
	if err != nil {
		return nil, err
	}

	// Decrypt the payload
	sigil, err := enchantrix.NewChaChaPolySigil(master)
	if err != nil {
		return nil, err
	}

	plaintext, err := sigil.Out(container.Payload)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	// Deserialize entries
	var entries []*Entry
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		return nil, ErrDecryptionFailed
	}

	entryMap := make(map[string]*Entry, len(entries))
	for _, e := range entries {
		entryMap[e.ID] = e
	}

	return &Store{
		path:    path,
		master:  master,
		salt:    salt,
		params:  &params,
		entries: entryMap,
	}, nil
}

// Put adds or replaces a key entry in the store. The key type and data size
// are validated before storage.
func (s *Store) Put(id string, keyType KeyType, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}
	if !keyType.IsValid() {
		return ErrInvalidKeyType
	}
	if expectedSize := keyType.KeySize(); expectedSize > 0 && len(raw) != expectedSize {
		return fmt.Errorf("%w: expected %d bytes for %s, got %d", ErrInvalidKeySize, expectedSize, keyType, len(raw))
	}
	if _, exists := s.entries[id]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateKey, id)
	}

	keyData := make([]byte, len(raw))
	copy(keyData, raw)

	s.entries[id] = &Entry{
		ID:        id,
		Type:      keyType,
		KeyData:   keyData,
		CreatedAt: time.Now().UTC(),
	}

	return nil
}

// PutEntry adds an entry with full metadata. If Label or Metadata are needed,
// use this instead of Put.
func (s *Store) PutEntry(entry *Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}
	if !entry.Type.IsValid() {
		return ErrInvalidKeyType
	}
	if expectedSize := entry.Type.KeySize(); expectedSize > 0 && len(entry.KeyData) != expectedSize {
		return fmt.Errorf("%w: expected %d bytes for %s, got %d", ErrInvalidKeySize, expectedSize, entry.Type, len(entry.KeyData))
	}
	if _, exists := s.entries[entry.ID]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateKey, entry.ID)
	}

	s.entries[entry.ID] = entry.Clone()
	if s.entries[entry.ID].CreatedAt.IsZero() {
		s.entries[entry.ID].CreatedAt = time.Now().UTC()
	}

	return nil
}

// Get retrieves a key entry by ID. Returns a clone to prevent mutation
// of the internal state.
func (s *Store) Get(id string) (*Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStoreClosed
	}

	entry, ok := s.entries[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, id)
	}

	return entry.Clone(), nil
}

// Delete removes a key entry from the store and zeroes its key material.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStoreClosed
	}

	entry, ok := s.entries[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, id)
	}

	// Zero key material before removing
	for i := range entry.KeyData {
		entry.KeyData[i] = 0
	}
	delete(s.entries, id)

	return nil
}

// List returns metadata for all stored keys. KeyData is never included
// in the returned entries.
func (s *Store) List() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		result = append(result, e.Redacted())
	}
	return result
}

// Import derives a key from a password using SHA-256 (matching Borg's
// DeriveKey behavior) and stores the derived key. The original password
// is never persisted — only the derived 32-byte key.
// Returns the generated key ID.
func (s *Store) Import(password string, label string) (string, error) {
	hash := sha256.Sum256([]byte(password))
	id := generateID()

	entry := &Entry{
		ID:      id,
		Type:    ChaCha256,
		KeyData: hash[:],
		Label:   label,
		Metadata: map[string]string{
			"derived_from": "password",
			"kdf":          "sha256",
		},
	}

	if err := s.PutEntry(entry); err != nil {
		return "", err
	}

	return id, nil
}

// Generate creates a new random key of the specified type and stores it.
// For X25519, both private and public keys are stored (private in KeyData,
// public in Metadata["public_key"]).
// Returns the generated key ID.
func (s *Store) Generate(keyType KeyType, label string) (string, error) {
	if !keyType.IsValid() {
		return "", ErrInvalidKeyType
	}

	id := generateID()
	var keyData []byte
	metadata := map[string]string{"generated": "true"}

	switch keyType {
	case X25519:
		curve := ecdh.X25519()
		privKey, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return "", fmt.Errorf("keystore: failed to generate X25519 key: %w", err)
		}
		keyData = privKey.Bytes()
		metadata["public_key"] = fmt.Sprintf("%x", privKey.PublicKey().Bytes())

	case ChaCha256, HMAC:
		size := keyType.KeySize()
		keyData = make([]byte, size)
		if _, err := io.ReadFull(rand.Reader, keyData); err != nil {
			return "", fmt.Errorf("keystore: failed to generate random key: %w", err)
		}

	case PGP:
		return "", fmt.Errorf("keystore: PGP key generation not yet supported, import instead")

	default:
		return "", ErrInvalidKeyType
	}

	entry := &Entry{
		ID:       id,
		Type:     keyType,
		KeyData:  keyData,
		Label:    label,
		Metadata: metadata,
	}

	if err := s.PutEntry(entry); err != nil {
		return "", err
	}

	return id, nil
}

// Save persists the store to disk as an encrypted Trix container.
func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return ErrStoreClosed
	}

	// Serialize entries
	entries := make([]*Entry, 0, len(s.entries))
	for _, e := range s.entries {
		entries = append(entries, e)
	}

	plaintext, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("keystore: failed to marshal entries: %w", err)
	}

	// Encrypt with master key
	sigil, err := enchantrix.NewChaChaPolySigil(s.master)
	if err != nil {
		return err
	}

	ciphertext, err := sigil.In(plaintext)
	if err != nil {
		return fmt.Errorf("keystore: failed to encrypt store: %w", err)
	}

	// Marshal Argon2 params for header
	paramsJSON, err := json.Marshal(s.params)
	if err != nil {
		return fmt.Errorf("keystore: failed to marshal params: %w", err)
	}

	// Marshal salt for header
	saltJSON, err := json.Marshal(s.salt)
	if err != nil {
		return fmt.Errorf("keystore: failed to marshal salt: %w", err)
	}

	// Build Trix container
	container := &trix.Trix{
		Header: map[string]interface{}{
			"format":        "enchantrix-keystore",
			"version":       "1.0",
			"salt":          json.RawMessage(saltJSON),
			"argon2_params": string(paramsJSON),
		},
		Payload: ciphertext,
	}

	encoded, err := trix.Encode(container, storeMagic, nil)
	if err != nil {
		return fmt.Errorf("keystore: failed to encode store: %w", err)
	}

	// Write atomically via temp file
	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, encoded, 0600); err != nil {
		return fmt.Errorf("keystore: failed to write store: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("keystore: failed to finalize store: %w", err)
	}

	return nil
}

// Close zeroes the master key and marks the store as closed.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	// Zero master key
	for i := range s.master {
		s.master[i] = 0
	}

	// Zero all key material
	for _, entry := range s.entries {
		for i := range entry.KeyData {
			entry.KeyData[i] = 0
		}
	}

	s.entries = nil
	s.closed = true
	return nil
}

// Path returns the file path of the store.
func (s *Store) Path() string {
	return s.path
}

// generateID creates a random hex ID suitable for key identification.
func generateID() string {
	b := make([]byte, 8)
	io.ReadFull(rand.Reader, b)
	return fmt.Sprintf("%x", b)
}
