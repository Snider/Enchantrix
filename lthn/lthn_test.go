package lthn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHash(t *testing.T) {
	hash := Hash("hello")
	assert.NotEmpty(t, hash)
}

func TestVerify(t *testing.T) {
	hash := Hash("hello")
	assert.True(t, Verify("hello", hash))
	assert.False(t, Verify("world", hash))
}
