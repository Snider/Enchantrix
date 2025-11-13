package enchantrix

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockWriter is a writer that fails on Write
type mockWriter struct{}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("write error")
}

// failOnSecondWrite is a writer that fails on the second write call.
type failOnSecondWrite struct {
	callCount int
}

func (m *failOnSecondWrite) Write(p []byte) (n int, err error) {
	m.callCount++
	if m.callCount > 1 {
		return 0, errors.New("second write failed")
	}
	return len(p), nil
}

func TestReverseSigil_Good(t *testing.T) {
	s := &ReverseSigil{}
	data := []byte("hello")
	reversed, err := s.In(data)
	assert.NoError(t, err)
	assert.Equal(t, "olleh", string(reversed))
	original, err := s.Out(reversed)
	assert.NoError(t, err)
	assert.Equal(t, "hello", string(original))
}

func TestReverseSigil_Ugly(t *testing.T) {
	s := &ReverseSigil{}
	// Test with empty string
	empty := []byte("")
	reversedEmpty, err := s.In(empty)
	assert.NoError(t, err)
	assert.Equal(t, "", string(reversedEmpty))

	// Test with nil
	reversedNil, err := s.In(nil)
	assert.NoError(t, err)
	assert.Nil(t, reversedNil)
}

func TestHexSigil_Good(t *testing.T) {
	s := &HexSigil{}
	data := []byte("hello")
	encoded, err := s.In(data)
	assert.NoError(t, err)
	assert.Equal(t, "68656c6c6f", string(encoded))
	decoded, err := s.Out(encoded)
	assert.NoError(t, err)
	assert.Equal(t, "hello", string(decoded))
}

func TestHexSigil_Bad(t *testing.T) {
	s := &HexSigil{}
	_, err := s.Out([]byte("not hex"))
	assert.Error(t, err)
}

func TestHexSigil_Ugly(t *testing.T) {
	s := &HexSigil{}
	// Test with empty string
	empty := []byte("")
	encodedEmpty, err := s.In(empty)
	assert.NoError(t, err)
	assert.Equal(t, "", string(encodedEmpty))

	// Test with nil
	encodedNil, err := s.In(nil)
	assert.NoError(t, err)
	assert.Nil(t, encodedNil)
}

func TestBase64Sigil_Good(t *testing.T) {
	s := &Base64Sigil{}
	data := []byte("hello")
	encoded, err := s.In(data)
	assert.NoError(t, err)
	assert.Equal(t, "aGVsbG8=", string(encoded))
	decoded, err := s.Out(encoded)
	assert.NoError(t, err)
	assert.Equal(t, "hello", string(decoded))
}

func TestBase64Sigil_Bad(t *testing.T) {
	s := &Base64Sigil{}
	_, err := s.Out([]byte("not base64"))
	assert.Error(t, err)
}

func TestBase64Sigil_Ugly(t *testing.T) {
	s := &Base64Sigil{}
	// Test with empty string
	empty := []byte("")
	encodedEmpty, err := s.In(empty)
	assert.NoError(t, err)
	assert.Equal(t, "", string(encodedEmpty))

	// Test with nil
	encodedNil, err := s.In(nil)
	assert.NoError(t, err)
	assert.Nil(t, encodedNil)
}

func TestGzipSigil_Good(t *testing.T) {
	s := &GzipSigil{}
	data := []byte("hello")
	compressed, err := s.In(data)
	assert.NoError(t, err)
	assert.NotEqual(t, data, compressed)
	decompressed, err := s.Out(compressed)
	assert.NoError(t, err)
	assert.Equal(t, "hello", string(decompressed))
}

func TestGzipSigil_Bad(t *testing.T) {
	s := &GzipSigil{}
	data := []byte("hello")

	// Test with invalid gzip data
	_, err := s.Out([]byte("not gzip"))
	assert.Error(t, err)

	// Test writer error
	s.writer = &mockWriter{}
	_, err = s.In(data)
	assert.Error(t, err)

	// Test closer error
	s.writer = &failOnSecondWrite{}
	_, err = s.In(data)
	assert.Error(t, err)
}

func TestGzipSigil_Ugly(t *testing.T) {
	s := &GzipSigil{}
	// Test with empty string
	empty := []byte("")
	compressedEmpty, err := s.In(empty)
	assert.NoError(t, err)
	decompressedEmpty, err := s.Out(compressedEmpty)
	assert.NoError(t, err)
	assert.Equal(t, "", string(decompressedEmpty))

	// Test with nil
	compressedNil, err := s.In(nil)
	assert.NoError(t, err)
	decompressedNil, err := s.Out(compressedNil)
	assert.NoError(t, err)
	assert.Nil(t, decompressedNil)
}

func TestJSONSigil_Good(t *testing.T) {
	s := &JSONSigil{Indent: true}
	data := []byte(`{"hello":"world"}`)
	indented, err := s.In(data)
	assert.NoError(t, err)
	assert.Equal(t, "{\n  \"hello\": \"world\"\n}", string(indented))

	s.Indent = false
	compacted, err := s.In(indented)
	assert.NoError(t, err)
	assert.Equal(t, `{"hello":"world"}`, string(compacted))

	// Out is a no-op
	outData, err := s.Out(data)
	assert.NoError(t, err)
	assert.Equal(t, data, outData)
}

func TestJSONSigil_Bad(t *testing.T) {
	s := &JSONSigil{}
	_, err := s.In([]byte("not json"))
	assert.Error(t, err)
}

func TestJSONSigil_Ugly(t *testing.T) {
	s := &JSONSigil{}
	// Test with empty string
	empty := []byte("")
	_, err := s.In(empty)
	assert.Error(t, err)

	// Test with nil
	_, err = s.In(nil)
	assert.Error(t, err)
}

func TestHashSigils_Good(t *testing.T) {
	// Using the input "hello" for all hash tests
	data := []byte("hello")

	// A map of hash names to their expected hex-encoded output for the input "hello"
	expectedHashes := map[string]string{
		"md4":         "866437cb7a794bce2b727acc0362ee27",
		"md5":         "5d41402abc4b2a76b9719d911017c592",
		"sha1":        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
		"sha224":      "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193",
		"sha256":      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		"sha384":      "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f",
		"sha512":      "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
		"ripemd160":   "108f07b8382412612c048d07d13f814118445acd",
		"sha3-224":    "b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81",
		"sha3-256":    "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392",
		"sha3-384":    "720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1330ff07c0fddee54699a4c3ee0ee9d887",
		"sha3-512":    "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976",
		"sha512-224":  "fe8509ed1fb7dcefc27e6ac1a80eddbec4cb3d2c6fe565244374061c",
		"sha512-256":  "e30d87cfa2a75db545eac4d61baf970366a8357c7f72fa95b52d0accb698f13a",
		"blake2s-256": "19213bacc58dee6dbde3ceb9a47cbb330b3d86f8cca8997eb00be456f140ca25",
		"blake2b-256": "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf",
		"blake2b-384": "85f19170be541e7774da197c12ce959b91a280b2f23e3113d6638a3335507ed72ddc30f81244dbe9fa8d195c23bceb7e",
		"blake2b-512": "e4cfa39a3d37be31c59609e807970799caa68a19bfaa15135f165085e01d41a65ba1e1b146aeb6bd0092b49eac214c103ccfa3a365954bbbe52f74a2b3620c94",
	}

	for name, expectedHex := range expectedHashes {
		t.Run(name, func(t *testing.T) {
			s, err := NewSigil(name)
			assert.NoError(t, err, "Failed to create sigil: %s", name)

			hashed, err := s.In(data)
			assert.NoError(t, err, "Hashing failed for sigil: %s", name)
			assert.Equal(t, expectedHex, hex.EncodeToString(hashed), "Hash mismatch for sigil: %s", name)

			// Also test the Out function, which should be a no-op
			unhashed, err := s.Out(hashed)
			assert.NoError(t, err, "Out failed for sigil: %s", name)
			assert.Equal(t, hashed, unhashed, "Out should be a no-op for sigil: %s", name)
		})
	}
}

func TestHashSigil_Bad(t *testing.T) {
	// 99 is not a valid crypto.Hash value
	s := NewHashSigil(99)
	data := []byte("hello")
	_, err := s.In(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "hash algorithm not available")
}

func TestHashSigil_Ugly(t *testing.T) {
	s, err := NewSigil("sha256")
	assert.NoError(t, err)

	// Test with empty string
	empty := []byte("")
	hashedEmpty, err := s.In(empty)
	assert.NoError(t, err)
	assert.NotEmpty(t, hashedEmpty)

	// Test with nil
	hashedNil, err := s.In(nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, hashedNil)
}
