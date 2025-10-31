package enchantrix_test

import (
	"testing"

	"github.com/Snider/Enchantrix/pkg/enchantrix"
	"github.com/stretchr/testify/assert"
)

func TestNewSigil(t *testing.T) {
	t.Run("ValidSigils", func(t *testing.T) {
		validNames := []string{
			"reverse", "hex", "base64", "gzip", "json", "json-indent",
			"md4", "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
			"ripemd160", "sha3-224", "sha3-256", "sha3-384", "sha3-512",
			"sha512-224", "sha512-256", "blake2s-256", "blake2b-256",
			"blake2b-384", "blake2b-512",
		}
		for _, name := range validNames {
			sigil, err := enchantrix.NewSigil(name)
			assert.NoError(t, err)
			assert.NotNil(t, sigil)
		}
	})

	t.Run("InvalidSigil", func(t *testing.T) {
		sigil, err := enchantrix.NewSigil("invalid-sigil-name")
		assert.Error(t, err)
		assert.Nil(t, sigil)
		assert.Contains(t, err.Error(), "unknown sigil name")
	})
}
