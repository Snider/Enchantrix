package enchantrix_test

import (
	"crypto"
	"encoding/hex"
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

// --- Sigil Tests ---

func TestReverseSigil(t *testing.T) {
	s := &enchantrix.ReverseSigil{}
	data := []byte("hello")
	reversed, err := s.In(data)
	assert.NoError(t, err)
	assert.Equal(t, "olleh", string(reversed))
	original, err := s.Out(reversed)
	assert.NoError(t, err)
	assert.Equal(t, "hello", string(original))

	// Ugly - empty string
	empty := []byte("")
	reversedEmpty, err := s.In(empty)
	assert.NoError(t, err)
	assert.Equal(t, "", string(reversedEmpty))
}

func TestHexSigil(t *testing.T) {
	s := &enchantrix.HexSigil{}
	data := []byte("hello")
	encoded, err := s.In(data)
	assert.NoError(t, err)
	assert.Equal(t, "68656c6c6f", string(encoded))
	decoded, err := s.Out(encoded)
	assert.NoError(t, err)
	assert.Equal(t, "hello", string(decoded))

	// Bad - invalid hex string
	_, err = s.Out([]byte("not hex"))
	assert.Error(t, err)
}

func TestBase64Sigil(t *testing.T) {
	s := &enchantrix.Base64Sigil{}
	data := []byte("hello")
	encoded, err := s.In(data)
	assert.NoError(t, err)
	assert.Equal(t, "aGVsbG8=", string(encoded))
	decoded, err := s.Out(encoded)
	assert.NoError(t, err)
	assert.Equal(t, "hello", string(decoded))

	// Bad - invalid base64 string
	_, err = s.Out([]byte("not base64"))
	assert.Error(t, err)
}

func TestGzipSigil(t *testing.T) {
	s := &enchantrix.GzipSigil{}
	data := []byte("hello")
	compressed, err := s.In(data)
	assert.NoError(t, err)
	assert.NotEqual(t, data, compressed)
	decompressed, err := s.Out(compressed)
	assert.NoError(t, err)
	assert.Equal(t, "hello", string(decompressed))

	// Bad - invalid gzip data
	_, err = s.Out([]byte("not gzip"))
	assert.Error(t, err)
}

func TestJSONSigil(t *testing.T) {
	s := &enchantrix.JSONSigil{Indent: true}
	data := []byte(`{"hello":"world"}`)
	indented, err := s.In(data)
	assert.NoError(t, err)
	assert.Equal(t, "{\n  \"hello\": \"world\"\n}", string(indented))
	s.Indent = false
	compacted, err := s.In(indented)
	assert.NoError(t, err)
	assert.Equal(t, `{"hello":"world"}`, string(compacted))

	// Bad - invalid json
	_, err = s.In([]byte("not json"))
	assert.Error(t, err)
}

func TestHashSigil(t *testing.T) {
	s := enchantrix.NewHashSigil(crypto.SHA256)
	data := []byte("hello")
	hashed, err := s.In(data)
	assert.NoError(t, err)
	expectedHash := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	assert.Equal(t, expectedHash, hex.EncodeToString(hashed))
	unhashed, err := s.Out(hashed)
	assert.NoError(t, err)
	assert.Equal(t, hashed, unhashed) // Out is a no-op
}
