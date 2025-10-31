package trix

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	Version = 2
)

var (
	ErrInvalidMagicNumber = errors.New("trix: invalid magic number")
	ErrInvalidVersion     = errors.New("trix: invalid version")
	ErrMagicNumberLength  = errors.New("trix: magic number must be 4 bytes long")
	ErrNilSigil           = errors.New("trix: sigil cannot be nil")
)

// Sigil defines the interface for a data transformer.
type Sigil interface {
	In(data []byte) ([]byte, error)
	Out(data []byte) ([]byte, error)
}

// Trix represents the structure of a .trix file.
type Trix struct {
	Header  map[string]interface{}
	Payload []byte
	Sigils  []Sigil `json:"-"` // Ignore Sigils during JSON marshaling
}

// Encode serializes a Trix struct into the .trix binary format.
func Encode(trix *Trix, magicNumber string) ([]byte, error) {
	if len(magicNumber) != 4 {
		return nil, ErrMagicNumberLength
	}

	headerBytes, err := json.Marshal(trix.Header)
	if err != nil {
		return nil, err
	}
	headerLength := uint32(len(headerBytes))

	buf := new(bytes.Buffer)

	// Write Magic Number
	if _, err := buf.WriteString(magicNumber); err != nil {
		return nil, err
	}

	// Write Version
	if err := buf.WriteByte(byte(Version)); err != nil {
		return nil, err
	}

	// Write Header Length
	if err := binary.Write(buf, binary.BigEndian, headerLength); err != nil {
		return nil, err
	}

	// Write JSON Header
	if _, err := buf.Write(headerBytes); err != nil {
		return nil, err
	}

	// Write Payload
	if _, err := buf.Write(trix.Payload); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Decode deserializes the .trix binary format into a Trix struct.
// Note: Sigils are not stored in the format and must be re-attached by the caller.
func Decode(data []byte, magicNumber string) (*Trix, error) {
	if len(magicNumber) != 4 {
		return nil, ErrMagicNumberLength
	}

	buf := bytes.NewReader(data)

	// Read and Verify Magic Number
	magic := make([]byte, 4)
	if _, err := io.ReadFull(buf, magic); err != nil {
		return nil, err
	}
	if string(magic) != magicNumber {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrInvalidMagicNumber, magicNumber, string(magic))
	}

	// Read and Verify Version
	version, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	if version != Version {
		return nil, ErrInvalidVersion
	}

	// Read Header Length
	var headerLength uint32
	if err := binary.Read(buf, binary.BigEndian, &headerLength); err != nil {
		return nil, err
	}

	// Read JSON Header
	headerBytes := make([]byte, headerLength)
	if _, err := io.ReadFull(buf, headerBytes); err != nil {
		return nil, err
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}

	// Read Payload
	payload, err := io.ReadAll(buf)
	if err != nil {
		return nil, err
	}

	return &Trix{
		Header:  header,
		Payload: payload,
	}, nil
}

// Pack applies the In method of all attached sigils to the payload.
func (t *Trix) Pack() error {
	for _, sigil := range t.Sigils {
		if sigil == nil {
			return ErrNilSigil
		}
		var err error
		t.Payload, err = sigil.In(t.Payload)
		if err != nil {
			return err
		}
	}
	return nil
}

// Unpack applies the Out method of all sigils in reverse order.
func (t *Trix) Unpack() error {
	for i := len(t.Sigils) - 1; i >= 0; i-- {
		sigil := t.Sigils[i]
		if sigil == nil {
			return ErrNilSigil
		}
		var err error
		t.Payload, err = sigil.Out(t.Payload)
		if err != nil {
			return err
		}
	}
	return nil
}

// ReverseSigil is an example Sigil that reverses the bytes of the payload.
type ReverseSigil struct{}

// In reverses the bytes of the data.
func (s *ReverseSigil) In(data []byte) ([]byte, error) {
	reversed := make([]byte, len(data))
	for i, j := 0, len(data)-1; i < len(data); i, j = i+1, j-1 {
		reversed[i] = data[j]
	}
	return reversed, nil
}

// Out reverses the bytes of the data.
func (s *ReverseSigil) Out(data []byte) ([]byte, error) {
	// Reversing the bytes again restores the original data.
	return s.In(data)
}
