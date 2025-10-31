package trix

import (
	"errors"
	"io"
	"reflect"
	"testing"
	"github.com/Snider/Enchantrix/pkg/crypt"
	"github.com/stretchr/testify/assert"
)

// TestTrixEncodeDecode_Good tests the ideal "happy path" scenario for encoding and decoding.
func TestTrixEncodeDecode_Good(t *testing.T) {
	header := map[string]interface{}{
		"content_type":         "application/octet-stream",
		"encryption_algorithm": "chacha20poly1035",
		"nonce":                "AAECAwQFBgcICQoLDA0ODxAREhMUFRY=",
		"created_at":           "2025-10-30T12:00:00Z",
	}
	payload := []byte("This is a secret message.")
	trix := &Trix{Header: header, Payload: payload}
	magicNumber := "TRIX"

	encoded, err := Encode(trix, magicNumber)
	assert.NoError(t, err)

	decoded, err := Decode(encoded, magicNumber)
	assert.NoError(t, err)

	assert.True(t, reflect.DeepEqual(trix.Header, decoded.Header))
	assert.Equal(t, trix.Payload, decoded.Payload)
}

// TestTrixEncodeDecode_Bad tests expected failure scenarios with well-formed but invalid inputs.
func TestTrixEncodeDecode_Bad(t *testing.T) {
	t.Run("MismatchedMagicNumber", func(t *testing.T) {
		trix := &Trix{Header: map[string]interface{}{}, Payload: []byte("payload")}
		encoded, err := Encode(trix, "GOOD")
		assert.NoError(t, err)

		_, err = Decode(encoded, "BAD!")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid magic number")
	})

	t.Run("InvalidMagicNumberLength", func(t *testing.T) {
		trix := &Trix{Header: map[string]interface{}{}, Payload: []byte("payload")}
		_, err := Encode(trix, "TOOLONG")
		assert.EqualError(t, err, "trix: magic number must be 4 bytes long")

		_, err = Decode([]byte{}, "SHORT")
		assert.EqualError(t, err, "trix: magic number must be 4 bytes long")
	})

	t.Run("MalformedHeaderJSON", func(t *testing.T) {
		// Create a Trix struct with a header that cannot be marshaled to JSON.
		header := map[string]interface{}{
			"unsupported": make(chan int), // Channels cannot be JSON-encoded
		}
		trix := &Trix{Header: header, Payload: []byte("payload")}
		_, err := Encode(trix, "TRIX")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "json: unsupported type")
	})
}

// TestTrixEncodeDecode_Ugly tests malicious or malformed inputs designed to cause crashes or panics.
func TestTrixEncodeDecode_Ugly(t *testing.T) {
	magicNumber := "UGLY"

	t.Run("CorruptedHeaderLength", func(t *testing.T) {
		// Manually construct a byte slice where the header length is larger than the actual data.
		var buf []byte
		buf = append(buf, []byte(magicNumber)...) // Magic Number
		buf = append(buf, byte(Version))          // Version
		// Header length of 1000, but the header is only 2 bytes long.
		buf = append(buf, []byte{0, 0, 3, 232}...) // BigEndian representation of 1000
		buf = append(buf, []byte("{}")...)        // A minimal valid JSON header
		buf = append(buf, []byte("payload")...)

		_, err := Decode(buf, magicNumber)
		assert.Error(t, err)
		assert.Equal(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("DataTooShort", func(t *testing.T) {
		// Data is too short to contain even the magic number.
		data := []byte("BAD")
		_, err := Decode(data, magicNumber)
		assert.Error(t, err)
	})

	t.Run("EmptyPayload", func(t *testing.T) {
		data := []byte{}
		_, err := Decode(data, magicNumber)
		assert.Error(t, err)
	})

	t.Run("FuzzedJSON", func(t *testing.T) {
		// A header that is technically valid but contains unexpected types.
		header := map[string]interface{}{
			"payload": map[string]interface{}{"nested": 123},
		}
		payload := []byte("some data")
		trix := &Trix{Header: header, Payload: payload}

		encoded, err := Encode(trix, magicNumber)
		assert.NoError(t, err)

		decoded, err := Decode(encoded, magicNumber)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
	})
}

// --- Sigil Tests ---

// FailingSigil is a helper for testing sigils that intentionally fail.
type FailingSigil struct {
	err error
}

func (s *FailingSigil) In(data []byte) ([]byte, error) {
	return nil, s.err
}
func (s *FailingSigil) Out(data []byte) ([]byte, error) {
	return nil, s.err
}

func TestPackUnpack_Good(t *testing.T) {
	originalPayload := []byte("hello world")
	trix := &Trix{
		Header:   map[string]interface{}{},
		Payload:  originalPayload,
		InSigils: []Sigil{&ReverseSigil{}, &ReverseSigil{}}, // Double reverse should be original
	}

	err := trix.Pack()
	assert.NoError(t, err)
	assert.Equal(t, originalPayload, trix.Payload) // Should be back to the original

	err = trix.Unpack()
	assert.NoError(t, err)
	assert.Equal(t, originalPayload, trix.Payload) // Should be back to the original again
}

func TestPackUnpack_Bad(t *testing.T) {
	expectedErr := errors.New("sigil failed")
	trix := &Trix{
		Header:   map[string]interface{}{},
		Payload:  []byte("some data"),
		InSigils: []Sigil{&ReverseSigil{}, &FailingSigil{err: expectedErr}},
	}

	err := trix.Pack()
	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
}

func TestPackUnpack_Ugly(t *testing.T) {
	t.Run("NilSigil", func(t *testing.T) {
		trix := &Trix{
			Header:   map[string]interface{}{},
			Payload:  []byte("some data"),
			InSigils: []Sigil{nil},
		}

		err := trix.Pack()
		assert.Error(t, err)
		assert.Equal(t, ErrNilSigil, err)
	})
}

// --- Checksum Tests ---

func TestChecksum_Good(t *testing.T) {
	trix := &Trix{
		Header:       map[string]interface{}{},
		Payload:      []byte("hello world"),
		ChecksumAlgo: crypt.SHA256,
	}
	encoded, err := Encode(trix, "CHCK")
	assert.NoError(t, err)

	decoded, err := Decode(encoded, "CHCK")
	assert.NoError(t, err)
	assert.Equal(t, trix.Payload, decoded.Payload)
}

func TestChecksum_Bad(t *testing.T) {
	trix := &Trix{
		Header:       map[string]interface{}{},
		Payload:      []byte("hello world"),
		ChecksumAlgo: crypt.SHA256,
	}
	encoded, err := Encode(trix, "CHCK")
	assert.NoError(t, err)

	// Tamper with the payload
	encoded[len(encoded)-1] = 0

	_, err = Decode(encoded, "CHCK")
	assert.Error(t, err)
	assert.Equal(t, ErrChecksumMismatch, err)
}

func TestChecksum_Ugly(t *testing.T) {
	t.Run("MissingAlgoInHeader", func(t *testing.T) {
		trix := &Trix{
			Header:       map[string]interface{}{},
			Payload:      []byte("hello world"),
			ChecksumAlgo: crypt.SHA256,
		}
		encoded, err := Encode(trix, "UGLY")
		assert.NoError(t, err)

		// Manually decode to tamper with the header
		decoded, err := Decode(encoded, "UGLY")
		assert.NoError(t, err)
		delete(decoded.Header, "checksum_algo")

		// Re-encode with the tampered header
		tamperedEncoded, err := Encode(decoded, "UGLY")
		assert.NoError(t, err)

		_, err = Decode(tamperedEncoded, "UGLY")
		assert.Error(t, err)
	})
}
