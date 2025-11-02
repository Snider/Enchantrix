package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	cfg := New()
	assert.NotNil(t, cfg)
	assert.Equal(t, 8080, cfg.HTTP.Port)

	newConfig := New()
	newConfig.HTTP.Port = 8081
	cfg.Update(newConfig)

	assert.Equal(t, 8081, cfg.Get().HTTP.Port)
}
