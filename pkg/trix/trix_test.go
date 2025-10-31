package trix

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeDecode(t *testing.T) {
	header := map[string]interface{}{
		"content_type":         "application/octet-stream",
		"encryption_algorithm": "chacha20poly1035",
		"nonce":                "AAECAwQFBgcICQoLDA0ODxAREhMUFRY=",
		"created_at":           "2025-10-30T12:00:00Z",
	}
	payload := []byte("This is a secret message.")

	trix := &Trix{
		Header:  header,
		Payload: payload,
	}

	encoded, err := Encode(trix)
	assert.NoError(t, err)

	decoded, err := Decode(encoded)
	assert.NoError(t, err)

	assert.True(t, reflect.DeepEqual(trix.Header, decoded.Header))
	assert.Equal(t, trix.Payload, decoded.Payload)
}
