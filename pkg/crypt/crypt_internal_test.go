package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEnsureRSA_Good tests that the RSA service is initialized correctly.
func TestEnsureRSA_Good(t *testing.T) {
	s := &Service{}
	s.ensureRSA()
	assert.NotNil(t, s.rsa)
}

// TestEnsureRSA_Bad tests that calling ensureRSA multiple times does not change the RSA service.
func TestEnsureRSA_Bad(t *testing.T) {
	s := &Service{}
	s.ensureRSA()
	rsa1 := s.rsa
	s.ensureRSA()
	rsa2 := s.rsa
	assert.Same(t, rsa1, rsa2)
}

// TestEnsureRSA_Ugly tests that ensureRSA works correctly on a service with a pre-initialized RSA service.
func TestEnsureRSA_Ugly(t *testing.T) {
	s := NewService() // NewService initializes the RSA service
	rsa1 := s.rsa
	s.ensureRSA()
	rsa2 := s.rsa
	assert.Same(t, rsa1, rsa2)
}
