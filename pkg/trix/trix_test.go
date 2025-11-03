package trix_test

import (
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/Snider/Enchantrix/pkg/crypt"
	"github.com/Snider/Enchantrix/pkg/trix"
	"github.com/stretchr/testify/assert"
)

// mockReader is an io.Reader that fails on demand.
type mockReader struct {
	readErr error
}

func (m *mockReader) Read(p []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	// Simulate a successful read by filling the buffer with zeros.
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// mockWriter is an io.Writer that fails on demand.
type mockWriter struct {
	writeErr error
}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return len(p), nil
}

// TestTrixEncodeDecode_Good tests the ideal "happy path" scenario for encoding and decoding.
func TestTrixEncodeDecode_Good(t *testing.T) {
	header := map[string]interface{}{
		"content_type":         "application/octet-stream",
		"encryption_algorithm": "chacha20poly1035",
		"nonce":                "AAECAwQFBgcICQoLDA0ODxAREhMUFRY=",
		"created_at":           "2025-10-30T12:00:00Z",
	}
	payload := []byte("This is a secret message.")
	trixOb := &trix.Trix{Header: header, Payload: payload}
	magicNumber := "TRIX"

	encoded, err := trix.Encode(trixOb, magicNumber, nil)
	assert.NoError(t, err)

	decoded, err := trix.Decode(encoded, magicNumber, nil)
	assert.NoError(t, err)

	assert.True(t, reflect.DeepEqual(trixOb.Header, decoded.Header))
	assert.Equal(t, trixOb.Payload, decoded.Payload)
}

// TestTrixEncodeDecode_Bad tests expected failure scenarios with well-formed but invalid inputs.
func TestTrixEncodeDecode_Bad(t *testing.T) {
	t.Run("MismatchedMagicNumber", func(t *testing.T) {
		trixOb := &trix.Trix{Header: map[string]interface{}{}, Payload: []byte("payload")}
		encoded, err := trix.Encode(trixOb, "GOOD", nil)
		assert.NoError(t, err)

		_, err = trix.Decode(encoded, "BAD!", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid magic number")
	})

	t.Run("InvalidMagicNumberLength", func(t *testing.T) {
		trixOb := &trix.Trix{Header: map[string]interface{}{}, Payload: []byte("payload")}
		_, err := trix.Encode(trixOb, "TOOLONG", nil)
		assert.EqualError(t, err, "trix: magic number must be 4 bytes long")

		_, err = trix.Decode([]byte{}, "SHORT", nil)
		assert.EqualError(t, err, "trix: magic number must be 4 bytes long")
	})

	t.Run("MalformedHeaderJSON", func(t *testing.T) {
		// Create a Trix struct with a header that cannot be marshaled to JSON.
		header := map[string]interface{}{
			"unsupported": make(chan int), // Channels cannot be JSON-encoded
		}
		trixOb := &trix.Trix{Header: header, Payload: []byte("payload")}
		_, err := trix.Encode(trixOb, "TRIX", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "json: unsupported type")
	})

	t.Run("HeaderTooLarge", func(t *testing.T) {
		data := make([]byte, trix.MaxHeaderSize+10)
		trixOb := &trix.Trix{
			Header:  map[string]interface{}{"large": string(data)},
			Payload: []byte("payload"),
		}
		encoded, err := trix.Encode(trixOb, "TRIX", nil)
		assert.NoError(t, err)

		_, err = trix.Decode(encoded, "TRIX", nil)
		assert.ErrorIs(t, err, trix.ErrHeaderTooLarge)
	})
}

// TestTrixEncodeDecode_Ugly tests malicious or malformed inputs designed to cause crashes or panics.
func TestTrixEncodeDecode_Ugly(t *testing.T) {
	magicNumber := "UGLY"

	t.Run("CorruptedHeaderLength", func(t *testing.T) {
		// Manually construct a byte slice where the header length is larger than the actual data.
		var buf []byte
		buf = append(buf, []byte(magicNumber)...)     // Magic Number
		buf = append(buf, byte(trix.Version))         // Version
		buf = append(buf, []byte{0, 0, 3, 232}...)    // BigEndian representation of 1000
		buf = append(buf, []byte("{}")...)           // A minimal valid JSON header
		buf = append(buf, []byte("payload")...)

		_, err := trix.Decode(buf, magicNumber, nil)
		assert.Error(t, err)
		assert.Equal(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("DataTooShort", func(t *testing.T) {
		data := []byte("BAD")
		_, err := trix.Decode(data, magicNumber, nil)
		assert.Error(t, err)
	})

	t.Run("EmptyPayload", func(t *testing.T) {
		data := []byte{}
		_, err := trix.Decode(data, magicNumber, nil)
		assert.Error(t, err)
	})

	t.Run("FuzzedJSON", func(t *testing.T) {
		header := map[string]interface{}{
			"payload": map[string]interface{}{"nested": 123},
		}
		payload := []byte("some data")
		trixOb := &trix.Trix{Header: header, Payload: payload}

		encoded, err := trix.Encode(trixOb, magicNumber, nil)
		assert.NoError(t, err)

		decoded, err := trix.Decode(encoded, magicNumber, nil)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
	})
}

// --- Sigil Tests ---

func TestPackUnpack_Good(t *testing.T) {
	originalPayload := []byte("hello world")
	trixOb := &trix.Trix{
		Header:   map[string]interface{}{},
		Payload:  originalPayload,
		InSigils: []string{"reverse", "reverse"}, // Double reverse should be original
	}

	err := trixOb.Pack()
	assert.NoError(t, err)
	assert.Equal(t, originalPayload, trixOb.Payload)

	err = trixOb.Unpack()
	assert.NoError(t, err)
	assert.Equal(t, originalPayload, trixOb.Payload)
}

func TestPackUnpack_Bad(t *testing.T) {
	trixOb := &trix.Trix{
		Header:   map[string]interface{}{},
		Payload:  []byte("some data"),
		InSigils: []string{"reverse", "invalid-sigil-name"},
	}

	err := trixOb.Pack()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown sigil name")

	trixOb.InSigils = []string{"hex"}
	trixOb.Payload = []byte("not hex")
	err = trixOb.Unpack()
	assert.Error(t, err)
}

func TestPackUnpack_Ugly(t *testing.T) {
	trixOb := &trix.Trix{
		Header:   map[string]interface{}{},
		Payload:  nil, // Nil payload
		InSigils: []string{"reverse"},
	}
	err := trixOb.Pack()
	assert.NoError(t, err) // Should handle nil payload gracefully

	err = trixOb.Unpack()
	assert.NoError(t, err)
}

// --- Checksum Tests ---

func TestChecksum_Good(t *testing.T) {
	trixOb := &trix.Trix{
		Header:       map[string]interface{}{},
		Payload:      []byte("hello world"),
		ChecksumAlgo: crypt.SHA256,
	}
	encoded, err := trix.Encode(trixOb, "CHCK", nil)
	assert.NoError(t, err)

	decoded, err := trix.Decode(encoded, "CHCK", nil)
	assert.NoError(t, err)
	assert.Equal(t, trixOb.Payload, decoded.Payload)
}

func TestChecksum_Bad(t *testing.T) {
	trixOb := &trix.Trix{
		Header:       map[string]interface{}{},
		Payload:      []byte("hello world"),
		ChecksumAlgo: crypt.SHA256,
	}
	encoded, err := trix.Encode(trixOb, "CHCK", nil)
	assert.NoError(t, err)

	encoded[len(encoded)-1] = 0 // Tamper with the payload

	_, err = trix.Decode(encoded, "CHCK", nil)
	assert.ErrorIs(t, err, trix.ErrChecksumMismatch)
}

func TestChecksum_Ugly(t *testing.T) {
	t.Run("MissingAlgoInHeader", func(t *testing.T) {
		trixOb := &trix.Trix{
			Header:       map[string]interface{}{},
			Payload:      []byte("hello world"),
			ChecksumAlgo: crypt.SHA256,
		}
		encoded, err := trix.Encode(trixOb, "UGLY", nil)
		assert.NoError(t, err)

		decoded, err := trix.Decode(encoded, "UGLY", nil)
		assert.NoError(t, err)
		delete(decoded.Header, "checksum_algo")

		tamperedEncoded, err := trix.Encode(decoded, "UGLY", nil)
		assert.NoError(t, err)

		_, err = trix.Decode(tamperedEncoded, "UGLY", nil)
		assert.Error(t, err)
	})
}

// --- Fuzz Tests ---

func FuzzDecode(f *testing.F) {
	validTrix := &trix.Trix{
		Header:  map[string]interface{}{"content_type": "text/plain"},
		Payload: []byte("hello world"),
	}
	validEncoded, _ := trix.Encode(validTrix, "FUZZ", nil)
	f.Add(validEncoded)

	var buf []byte
	buf = append(buf, []byte("UGLY")...)
	buf = append(buf, byte(trix.Version))
	buf = append(buf, []byte{0, 0, 3, 232}...)
	buf = append(buf, []byte("{}")...)
	buf = append(buf, []byte("payload")...)
	f.Add(buf)

	f.Add([]byte("short"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = trix.Decode(data, "FUZZ", nil)
	})
}

func TestTrixEncodeDecode_IOErrors(t *testing.T) {
	t.Run("EncodeWriteError", func(t *testing.T) {
		trixOb := &trix.Trix{Header: map[string]interface{}{}, Payload: []byte("payload")}
		_, err := trix.Encode(trixOb, "TRIX", &mockWriter{writeErr: errors.New("write error")})
		assert.Error(t, err)
	})

	t.Run("DecodeReadError", func(t *testing.T) {
		trixOb := &trix.Trix{Header: map[string]interface{}{}, Payload: []byte("payload")}
		encoded, err := trix.Encode(trixOb, "TRIX", nil)
		assert.NoError(t, err)

		_, err = trix.Decode(encoded, "TRIX", &mockReader{readErr: errors.New("read error")})
		assert.Error(t, err)
	})
}
