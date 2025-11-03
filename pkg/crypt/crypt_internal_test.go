package crypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnsureRSA(t *testing.T) {
	s := &Service{}
	s.ensureRSA()
	assert.NotNil(t, s.rsa)
}
