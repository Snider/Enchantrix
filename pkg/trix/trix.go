package trix

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const (
	MagicNumber = "TRIX"
	Version     = 2
)

var (
	ErrInvalidMagicNumber = errors.New("trix: invalid magic number")
	ErrInvalidVersion     = errors.New("trix: invalid version")
)

// Trix represents the structure of a .trix file.
type Trix struct {
	Header  map[string]interface{}
	Payload []byte
}

// Encode serializes a Trix struct into the .trix binary format.
func Encode(trix *Trix) ([]byte, error) {
	headerBytes, err := json.Marshal(trix.Header)
	if err != nil {
		return nil, err
	}
	headerLength := uint32(len(headerBytes))

	buf := new(bytes.Buffer)

	// Write Magic Number
	if _, err := buf.WriteString(MagicNumber); err != nil {
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
func Decode(data []byte) (*Trix, error) {
	buf := bytes.NewReader(data)

	// Read and Verify Magic Number
	magic := make([]byte, 4)
	if _, err := io.ReadFull(buf, magic); err != nil {
		return nil, err
	}
	if string(magic) != MagicNumber {
		return nil, ErrInvalidMagicNumber
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
