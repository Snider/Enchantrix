package crypt_test

import (
	"strings"
	"testing"

	"github.com/Snider/Enchantrix/pkg/crypt"
	"github.com/stretchr/testify/assert"
)

var service = crypt.NewService()

// --- Hashing Tests ---

func TestHash_Good(t *testing.T) {
	payload := "hello"
	// Test all supported hash types
	for _, hashType := range []crypt.HashType{crypt.LTHN, crypt.SHA512, crypt.SHA256, crypt.SHA1, crypt.MD5} {
		hash := service.Hash(hashType, payload)
		assert.NotEmpty(t, hash, "Hash should not be empty for type %s", hashType)
	}
}

func TestHash_Bad(t *testing.T) {
	// Using an unsupported hash type should default to SHA256
	hash := service.Hash("unsupported", "hello")
	expectedHash := service.Hash(crypt.SHA256, "hello")
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
		for _, hashType := range []crypt.HashType{crypt.LTHN, crypt.SHA512, crypt.SHA256, crypt.SHA1, crypt.MD5} {
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
	assert.False(t, service.Luhn("1"), "Should be false for single digit")
}

func TestLuhn_Ugly(t *testing.T) {
	assert.False(t, service.Luhn(""), "Should be false for empty string")
	assert.False(t, service.Luhn(" 1 2 3 "), "Should handle spaces but result in false")
	assert.False(t, service.Luhn("!@#$%^&*()"), "Should be false for special characters")
}

// Fletcher16 Tests
func TestFletcher16_Good(t *testing.T) {
	assert.Equal(t, uint16(0xC8F0), service.Fletcher16("abcde"))
	assert.Equal(t, uint16(0x2057), service.Fletcher16("abcdef"))
	assert.Equal(t, uint16(0x0627), service.Fletcher16("abcdefgh"))
}

func TestFletcher16_Ugly(t *testing.T) {
	assert.Equal(t, uint16(0), service.Fletcher16(""), "Checksum of empty string should be 0")
	assert.Equal(t, uint16(0), service.Fletcher16("\x00"), "Checksum of null byte should be 0")
	assert.NotEqual(t, uint16(0), service.Fletcher16(" "), "Checksum of space should not be 0")
}

// Fletcher32 Tests
func TestFletcher32_Good(t *testing.T) {
	assert.Equal(t, uint32(0xF04FC729), service.Fletcher32("abcde"))
	assert.Equal(t, uint32(0x56502D2A), service.Fletcher32("abcdef"))
	assert.Equal(t, uint32(0xEBE19591), service.Fletcher32("abcdefgh"))
}

func TestFletcher32_Ugly(t *testing.T) {
	assert.Equal(t, uint32(0), service.Fletcher32(""), "Checksum of empty string should be 0")
	// Test odd length string to check padding
	assert.NotEqual(t, uint32(0), service.Fletcher32("a"), "Checksum of odd length string")
	assert.NotEqual(t, uint32(0), service.Fletcher32(" "), "Checksum of space should not be 0")
}

// Fletcher64 Tests
func TestFletcher64_Good(t *testing.T) {
	assert.Equal(t, uint64(0xc8c6c527646362c6), service.Fletcher64("abcde"))
	assert.Equal(t, uint64(0xc8c72b276463c8c6), service.Fletcher64("abcdef"))
	assert.Equal(t, uint64(0x312e2b28cccac8c6), service.Fletcher64("abcdefgh"))
}

func TestFletcher64_Ugly(t *testing.T) {
	assert.Equal(t, uint64(0), service.Fletcher64(""), "Checksum of empty string should be 0")
	// Test different length strings to check padding
	assert.NotEqual(t, uint64(0), service.Fletcher64("a"), "Checksum of length 1 string")
	assert.NotEqual(t, uint64(0), service.Fletcher64("ab"), "Checksum of length 2 string")
	assert.NotEqual(t, uint64(0), service.Fletcher64("abc"), "Checksum of length 3 string")
	assert.NotEqual(t, uint64(0), service.Fletcher64(" "), "Checksum of space should not be 0")
}


// --- RSA Tests ---

func TestRSA_Good(t *testing.T) {
	pubKey, privKey, err := service.GenerateRSAKeyPair(2048)
	assert.NoError(t, err)
	assert.NotNil(t, pubKey)
	assert.NotNil(t, privKey)

	// Test encryption and decryption
	message := []byte("secret message")
	label := []byte("test label")
	ciphertext, err := service.EncryptRSA(pubKey, message, label)
	assert.NoError(t, err)
	plaintext, err := service.DecryptRSA(privKey, ciphertext, label)
	assert.NoError(t, err)
	assert.Equal(t, message, plaintext)
}

func TestRSA_Bad(t *testing.T) {
	// Test with a key size that is too small
	_, _, err := service.GenerateRSAKeyPair(1024)
	assert.Error(t, err)

	// Test decryption with the wrong key
	pubKey, privKey, err := service.GenerateRSAKeyPair(2048)
	assert.NoError(t, err)
	_, otherPrivKey, err := service.GenerateRSAKeyPair(2048)
	assert.NoError(t, err)
	message := []byte("secret message")
	ciphertext, err := service.EncryptRSA(pubKey, message, nil)
	assert.NoError(t, err)
	_, err = service.DecryptRSA(otherPrivKey, ciphertext, nil)
	assert.Error(t, err)

	// Test decryption with wrong label
	label1 := []byte("label1")
	label2 := []byte("label2")
	ciphertext, err = service.EncryptRSA(pubKey, message, label1)
	assert.NoError(t, err)
	_, err = service.DecryptRSA(privKey, ciphertext, label2)
	assert.Error(t, err)
}

func TestRSA_Ugly(t *testing.T) {
	// Test with malformed keys
	_, err := service.EncryptRSA([]byte("not a real key"), []byte("message"), nil)
	assert.Error(t, err)

	_, err = service.DecryptRSA([]byte("not a real key"), []byte("message"), nil)
	assert.Error(t, err)

	// Test with empty message
	pubKey, privKey, err := service.GenerateRSAKeyPair(2048)
	assert.NoError(t, err)
	message := []byte("")
	ciphertext, err := service.EncryptRSA(pubKey, message, nil)
	assert.NoError(t, err)
	plaintext, err := service.DecryptRSA(privKey, ciphertext, nil)
	assert.NoError(t, err)
	assert.Equal(t, message, plaintext)
}
