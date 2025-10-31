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

	magicNumber := "TRIX"
	encoded, err := Encode(trix, magicNumber)
	assert.NoError(t, err)

	decoded, err := Decode(encoded, magicNumber)
	assert.NoError(t, err)

	assert.True(t, reflect.DeepEqual(trix.Header, decoded.Header))
	assert.Equal(t, trix.Payload, decoded.Payload)
}

func TestEncodeDecode_InvalidMagicNumber(t *testing.T) {
	header := map[string]interface{}{
		"content_type": "application/octet-stream",
	}
	payload := []byte("This is a secret message.")

	trix := &Trix{
		Header:  header,
		Payload: payload,
	}

	magicNumber := "TRIX"
	wrongMagicNumber := "XXXX"
	encoded, err := Encode(trix, magicNumber)
	assert.NoError(t, err)

	_, err = Decode(encoded, wrongMagicNumber)
	assert.Error(t, err)
	assert.EqualError(t, err, "trix: invalid magic number: expected XXXX, got TRIX")
}

func TestEncode_InvalidMagicNumberLength(t *testing.T) {
	header := map[string]interface{}{
		"content_type": "application/octet-stream",
	}
	payload := []byte("This is a secret message.")

	trix := &Trix{
		Header:  header,
		Payload: payload,
	}

	magicNumber := "TOOLONG"
	_, err := Encode(trix, magicNumber)
	assert.Error(t, err)
	assert.EqualError(t, err, "trix: magic number must be 4 bytes long")
}

func TestDecode_InvalidMagicNumberLength(t *testing.T) {
	header := map[string]interface{}{
		"content_type": "application/octet-stream",
	}
	payload := []byte("This is a secret message.")

	trix := &Trix{
		Header:  header,
		Payload: payload,
	}

	magicNumber := "TRIX"
	encoded, err := Encode(trix, magicNumber)
	assert.NoError(t, err)

	invalidMagicNumber := "SHORT"
	_, err = Decode(encoded, invalidMagicNumber)
	assert.Error(t, err)
	assert.EqualError(t, err, "trix: magic number must be 4 bytes long")
}
