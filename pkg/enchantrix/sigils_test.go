package enchantrix_test

import (
	"crypto"
	"encoding/hex"
	"testing"

	"github.com/Snider/Enchantrix/pkg/enchantrix"
	"github.com/stretchr/testify/assert"
)

func TestReverseSigil(t *testing.T) {
	s := &enchantrix.ReverseSigil{}
	data := []byte("hello")
	reversed, err := s.In(data)
	assert.NoError(t, err)
	assert.Equal(t, "olleh", string(reversed))
	original, err := s.Out(reversed)
	assert.NoError(t, err)
	assert.Equal(t, "hello", string(original))
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
	assert.Equal(t, hashed, unhashed)
}
