package keystore

import "time"

// Entry represents a single key stored in the key store.
// KeyData is only populated when accessed through the Store; it is
// never included in List() results to prevent accidental exposure.
type Entry struct {
	// ID is the unique identifier for this key entry.
	ID string `json:"id"`
	// Type identifies the cryptographic algorithm this key is for.
	Type KeyType `json:"type"`
	// KeyData holds the raw key material. This field is zeroed on Delete
	// and omitted from List() responses.
	KeyData []byte `json:"key_data,omitempty"`
	// Label is a human-readable name for the key.
	Label string `json:"label"`
	// CreatedAt records when the key was added to the store.
	CreatedAt time.Time `json:"created_at"`
	// Metadata holds optional key-value pairs (e.g. algorithm params, origin).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Clone returns a deep copy of the entry, including key data.
func (e *Entry) Clone() *Entry {
	clone := &Entry{
		ID:        e.ID,
		Type:      e.Type,
		Label:     e.Label,
		CreatedAt: e.CreatedAt,
	}
	if e.KeyData != nil {
		clone.KeyData = make([]byte, len(e.KeyData))
		copy(clone.KeyData, e.KeyData)
	}
	if e.Metadata != nil {
		clone.Metadata = make(map[string]string, len(e.Metadata))
		for k, v := range e.Metadata {
			clone.Metadata[k] = v
		}
	}
	return clone
}

// Redacted returns a copy with KeyData removed, suitable for listing.
func (e *Entry) Redacted() Entry {
	return Entry{
		ID:        e.ID,
		Type:      e.Type,
		Label:     e.Label,
		CreatedAt: e.CreatedAt,
		Metadata:  e.Metadata,
	}
}
