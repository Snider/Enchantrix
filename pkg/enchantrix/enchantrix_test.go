package enchantrix_test

import (
	"errors"
	"testing"

	"github.com/Snider/Enchantrix/pkg/enchantrix"
	"github.com/stretchr/testify/assert"
)

// --- Transmute Tests ---

func TestTransmute_Good(t *testing.T) {
	data := []byte("hello")
	sigils := []enchantrix.Sigil{
		&enchantrix.ReverseSigil{},
		&enchantrix.HexSigil{},
	}
	result, err := enchantrix.Transmute(data, sigils)
	assert.NoError(t, err)
	assert.Equal(t, "6f6c6c6568", string(result))
}

type errorSigil struct{}

func (s *errorSigil) In(data []byte) ([]byte, error) {
	return nil, errors.New("sigil error")
}
func (s *errorSigil) Out(data []byte) ([]byte, error) {
	return nil, errors.New("sigil error")
}

func TestTransmute_Bad(t *testing.T) {
	data := []byte("hello")
	sigils := []enchantrix.Sigil{
		&enchantrix.ReverseSigil{},
		&errorSigil{},
	}
	_, err := enchantrix.Transmute(data, sigils)
	assert.Error(t, err)
}

// --- Factory Tests ---

func TestNewSigil_Good(t *testing.T) {
	validNames := []string{
		"reverse", "hex", "base64", "gzip", "json", "json-indent",
		"md4", "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
		"ripemd160", "sha3-224", "sha3-256", "sha3-384", "sha3-512",
		"sha512-224", "sha512-256", "blake2s-256", "blake2b-256",
		"blake2b-384", "blake2b-512",
	}
	for _, name := range validNames {
		sigil, err := enchantrix.NewSigil(name)
		assert.NoError(t, err, "Failed to create sigil: %s", name)
		assert.NotNil(t, sigil, "Sigil should not be nil for name: %s", name)
	}
}

func TestNewSigil_Bad(t *testing.T) {
	sigil, err := enchantrix.NewSigil("invalid-sigil-name")
	assert.Error(t, err)
	assert.Nil(t, sigil)
	assert.Contains(t, err.Error(), "unknown sigil name")
}
