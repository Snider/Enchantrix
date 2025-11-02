package crypt

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/Snider/Enchantrix/pkg/crypt/std/lthn"
	"github.com/Snider/Enchantrix/pkg/crypt/std/rsa"
)

// Service is the main struct for the crypt service.
type Service struct {
	rsa *rsa.Service
}

// NewService creates a new crypt Service and initialises its embedded RSA service.
func NewService() *Service {
	return &Service{
		rsa: rsa.NewService(),
	}
}

// HashType defines the supported hashing algorithms.
type HashType string

const (
	LTHN   HashType = "lthn"
	SHA512 HashType = "sha512"
	SHA256 HashType = "sha256"
	SHA1   HashType = "sha1"
	MD5    HashType = "md5"
)

// --- Hashing ---

// Hash computes a hash of the payload using the specified algorithm.
func (s *Service) Hash(lib HashType, payload string) string {
	switch lib {
	case LTHN:
		return lthn.Hash(payload)
	case SHA512:
		hash := sha512.Sum512([]byte(payload))
		return hex.EncodeToString(hash[:])
	case SHA1:
		hash := sha1.Sum([]byte(payload))
		return hex.EncodeToString(hash[:])
	case MD5:
		hash := md5.Sum([]byte(payload))
		return hex.EncodeToString(hash[:])
	case SHA256:
		fallthrough
	default:
		hash := sha256.Sum256([]byte(payload))
		return hex.EncodeToString(hash[:])
	}
}

// --- Checksums ---

// Luhn validates a number using the Luhn algorithm.
func (s *Service) Luhn(payload string) bool {
	payload = strings.ReplaceAll(payload, " ", "")
	if len(payload) <= 1 {
		return false
	}

	sum := 0
	isSecond := len(payload)%2 == 0
	for _, r := range payload {
		digit, err := strconv.Atoi(string(r))
		if err != nil {
			return false // Contains non-digit
		}

		if isSecond {
			digit = digit * 2
			if digit > 9 {
				digit = digit - 9
			}
		}

		sum += digit
		isSecond = !isSecond
	}
	return sum%10 == 0
}

// Fletcher16 computes the Fletcher-16 checksum.
func (s *Service) Fletcher16(payload string) uint16 {
	data := []byte(payload)
	var sum1, sum2 uint16
	for _, b := range data {
		sum1 = (sum1 + uint16(b)) % 255
		sum2 = (sum2 + sum1) % 255
	}
	return (sum2 << 8) | sum1
}

// Fletcher32 computes the Fletcher-32 checksum.
func (s *Service) Fletcher32(payload string) uint32 {
	data := []byte(payload)
	if len(data)%2 != 0 {
		data = append(data, 0)
	}

	var sum1, sum2 uint32
	for i := 0; i < len(data); i += 2 {
		val := binary.LittleEndian.Uint16(data[i : i+2])
		sum1 = (sum1 + uint32(val)) % 65535
		sum2 = (sum2 + sum1) % 65535
	}
	return (sum2 << 16) | sum1
}

// Fletcher64 computes the Fletcher-64 checksum.
func (s *Service) Fletcher64(payload string) uint64 {
	data := []byte(payload)
	if len(data)%4 != 0 {
		padding := 4 - (len(data) % 4)
		data = append(data, make([]byte, padding)...)
	}

	var sum1, sum2 uint64
	for i := 0; i < len(data); i += 4 {
		val := binary.LittleEndian.Uint32(data[i : i+4])
		sum1 = (sum1 + uint64(val)) % 4294967295
		sum2 = (sum2 + sum1) % 4294967295
	}
	return (sum2 << 32) | sum1
}

// --- RSA ---

// ensureRSA initializes the RSA service if it is not already.
func (s *Service) ensureRSA() {
	if s.rsa == nil {
		s.rsa = rsa.NewService()
	}
}

// GenerateRSAKeyPair creates a new RSA key pair.
func (s *Service) GenerateRSAKeyPair(bits int) (publicKey, privateKey []byte, err error) {
	s.ensureRSA()
	return s.rsa.GenerateKeyPair(bits)
}

// EncryptRSA encrypts data with a public key.
func (s *Service) EncryptRSA(publicKey, data, label []byte) ([]byte, error) {
	s.ensureRSA()
	return s.rsa.Encrypt(publicKey, data, label)
}

// DecryptRSA decrypts data with a private key.
func (s *Service) DecryptRSA(privateKey, ciphertext, label []byte) ([]byte, error) {
	s.ensureRSA()
	return s.rsa.Decrypt(privateKey, ciphertext, label)
}