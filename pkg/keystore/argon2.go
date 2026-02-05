package keystore

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	// Default Argon2id parameters
	defaultArgon2Time    = 1
	defaultArgon2Memory  = 64 * 1024 // 64 MB
	defaultArgon2Threads = 4
	defaultArgon2KeyLen  = 32
	saltSize             = 16
)

// Argon2Params holds the parameters for Argon2id key derivation.
type Argon2Params struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"key_len"`
}

// DefaultArgon2Params returns the default Argon2id parameters.
func DefaultArgon2Params() *Argon2Params {
	return &Argon2Params{
		Time:    defaultArgon2Time,
		Memory:  defaultArgon2Memory,
		Threads: defaultArgon2Threads,
		KeyLen:  defaultArgon2KeyLen,
	}
}

// DeriveKey derives a cryptographic key from a password and salt using Argon2id.
// If salt is nil, a random 16-byte salt is generated.
// Returns the derived key and the salt used.
func DeriveKey(password string, salt []byte, params *Argon2Params) (key []byte, usedSalt []byte, err error) {
	if params == nil {
		params = DefaultArgon2Params()
	}

	if salt == nil {
		salt = make([]byte, saltSize)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, nil, err
		}
	}

	key = argon2.IDKey(
		[]byte(password),
		salt,
		params.Time,
		params.Memory,
		params.Threads,
		params.KeyLen,
	)

	return key, salt, nil
}
