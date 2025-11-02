package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnsureRSA_Good(t *testing.T) {
	s := &Service{}
	assert.Nil(t, s.rsa, "s.rsa should be nil initially")
	s.ensureRSA()
	assert.NotNil(t, s.rsa, "s.rsa should not be nil after ensureRSA()")
}

func TestEnsureRSA_Bad(t *testing.T) {
	// Not really a "bad" case here in terms of invalid input,
	// but we can test that calling it twice is safe.
	s := &Service{}
	s.ensureRSA()
	rsaInstance := s.rsa
	s.ensureRSA()
	assert.Same(t, rsaInstance, s.rsa, "s.rsa should be the same instance after second call")
}
