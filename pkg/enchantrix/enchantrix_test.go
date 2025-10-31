package enchantrix_test

import (
	"testing"

	"github.com/Snider/Enchantrix/pkg/enchantrix"
	"github.com/stretchr/testify/assert"
)

func TestTransmute(t *testing.T) {
	data := []byte("hello")
	sigils := []enchantrix.Sigil{
		&enchantrix.ReverseSigil{},
		&enchantrix.HexSigil{},
	}
	result, err := enchantrix.Transmute(data, sigils)
	assert.NoError(t, err)
	assert.Equal(t, "6f6c6c6568", string(result))
}
