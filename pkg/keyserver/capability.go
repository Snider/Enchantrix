package keyserver

import (
	"fmt"
	"strings"
)

// Capability represents a permission to perform a specific operation on a
// specific key (or all keys with wildcard "*").
//
// Format: "operation:keyID" — e.g. "encrypt:abc123" or "decrypt:*"
type Capability struct {
	Operation string // encrypt, decrypt, sign, verify, list, derive, delete
	KeyID     string // specific key ID or "*" for all
}

// Valid operation names for capability strings.
var validOperations = map[string]bool{
	"encrypt": true,
	"decrypt": true,
	"sign":    true,
	"verify":  true,
	"list":    true,
	"derive":  true,
	"delete":  true,
	"generate": true,
	"import":  true,
	"wrap":    true,
	"unwrap":  true,
}

// ParseCapability parses a capability string like "encrypt:key-abc".
func ParseCapability(s string) (Capability, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return Capability{}, fmt.Errorf("keyserver: invalid capability format %q (expected op:keyID)", s)
	}

	op := strings.TrimSpace(parts[0])
	keyID := strings.TrimSpace(parts[1])

	if !validOperations[op] {
		return Capability{}, fmt.Errorf("keyserver: unknown operation %q", op)
	}
	if keyID == "" {
		return Capability{}, fmt.Errorf("keyserver: empty key ID in capability %q", s)
	}

	return Capability{Operation: op, KeyID: keyID}, nil
}

// ParseCapabilities parses a comma-separated list of capability strings.
func ParseCapabilities(s string) ([]Capability, error) {
	parts := strings.Split(s, ",")
	caps := make([]Capability, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		cap, err := ParseCapability(p)
		if err != nil {
			return nil, err
		}
		caps = append(caps, cap)
	}
	return caps, nil
}

// Matches reports whether this capability grants permission for the given
// operation on the given key.
func (c Capability) Matches(op, keyID string) bool {
	if c.Operation != op {
		return false
	}
	return c.KeyID == "*" || c.KeyID == keyID
}

// String returns the canonical string form "operation:keyID".
func (c Capability) String() string {
	return c.Operation + ":" + c.KeyID
}
