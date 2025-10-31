package crypt

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var service = NewService()

// --- Hashing Tests ---

func TestHash_Good(t *testing.T) {
	payload := "hello"
	// Test all supported hash types
	for _, hashType := range []HashType{LTHN, SHA512, SHA256, SHA1, MD5} {
		hash := service.Hash(hashType, payload)
		assert.NotEmpty(t, hash, "Hash should not be empty for type %s", hashType)
	}
}

func TestHash_Bad(t *testing.T) {
	// Using an unsupported hash type should default to SHA256
	hash := service.Hash("unsupported", "hello")
	expectedHash := service.Hash(SHA256, "hello")
	assert.Equal(t, expectedHash, hash)
}

func TestHash_Ugly(t *testing.T) {
	// Test with potentially problematic inputs
	testCases := []string{
		"",                      // Empty string
		" ",                     // Whitespace
		"\x00\x01\x02\x03\x04",  // Null bytes
		strings.Repeat("a", 1024*1024), // Large payload (1MB)
		"こんにちは",              // Unicode characters
	}

	for _, tc := range testCases {
		for _, hashType := range []HashType{LTHN, SHA512, SHA256, SHA1, MD5} {
			hash := service.Hash(hashType, tc)
			assert.NotEmpty(t, hash, "Hash for ugly input should not be empty for type %s", hashType)
		}
	}
}

// --- Checksum Tests ---

// Luhn Tests
func TestLuhn_Good(t *testing.T) {
	assert.True(t, service.Luhn("79927398713"))
}

func TestLuhn_Bad(t *testing.T) {
	assert.False(t, service.Luhn("79927398714"), "Should fail for incorrect checksum")
	assert.False(t, service.Luhn("7992739871a"), "Should fail for non-numeric input")
}

func TestLuhn_Ugly(t *testing.T) {
	assert.False(t, service.Luhn(""), "Should be false for empty string")
	assert.False(t, service.Luhn(" 1 2 3 "), "Should handle spaces but result in false")
}

// Fletcher16 Tests
func TestFletcher16_Good(t *testing.T) {
	assert.Equal(t, uint16(0xC8F0), service.Fletcher16("abcde"))
	assert.Equal(t, uint16(0x2057), service.Fletcher16("abcdef"))
	assert.Equal(t, uint16(0x0627), service.Fletcher16("abcdefgh"))
}

func TestFletcher16_Bad(t *testing.T) {
	// No obviously "bad" inputs that don't fall into "ugly"
	// For Fletcher, any string is a valid input.
}

func TestFletcher16_Ugly(t *testing.T) {
	assert.Equal(t, uint16(0), service.Fletcher16(""), "Checksum of empty string should be 0")
}

// Fletcher32 Tests
func TestFletcher32_Good(t *testing.T) {
	assert.Equal(t, uint32(0xF04FC729), service.Fletcher32("abcde"))
	assert.Equal(t, uint32(0x56502D2A), service.Fletcher32("abcdef"))
	assert.Equal(t, uint32(0xEBE19591), service.Fletcher32("abcdefgh"))
}

func TestFletcher32_Bad(t *testing.T) {
	// Any string is a valid input.
}

func TestFletcher32_Ugly(t *testing.T) {
	assert.Equal(t, uint32(0), service.Fletcher32(""), "Checksum of empty string should be 0")
}

// Fletcher64 Tests
func TestFletcher64_Good(t *testing.T) {
	assert.Equal(t, uint64(0xc8c6c527646362c6), service.Fletcher64("abcde"))
	assert.Equal(t, uint64(0xc8c72b276463c8c6), service.Fletcher64("abcdef"))
	assert.Equal(t, uint64(0x312e2b28cccac8c6), service.Fletcher64("abcdefgh"))
}

func TestFletcher64_Bad(t *testing.T) {
	// Any string is a valid input.
}

func TestFletcher64_Ugly(t *testing.T) {
	assert.Equal(t, uint64(0), service.Fletcher64(""), "Checksum of empty string should be 0")
}
