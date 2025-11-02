package trix

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Snider/Enchantrix/pkg/crypt"
	"github.com/Snider/Enchantrix/pkg/enchantrix"
)

const (
	Version       = 2
	MaxHeaderSize = 16 * 1024 * 1024 // 16 MB
)

var (
	ErrInvalidMagicNumber = errors.New("trix: invalid magic number")
	ErrInvalidVersion     = errors.New("trix: invalid version")
	ErrMagicNumberLength  = errors.New("trix: magic number must be 4 bytes long")
	ErrNilSigil           = errors.New("trix: sigil cannot be nil")
	ErrChecksumMismatch   = errors.New("trix: checksum mismatch")
	ErrHeaderTooLarge     = errors.New("trix: header size exceeds maximum allowed")
)

// Trix represents the structure of a .trix file.
type Trix struct {
	Header       map[string]interface{}
	Payload      []byte
	InSigils     []string `json:"-"` // Ignore Sigils during JSON marshaling
	OutSigils    []string `json:"-"` // Ignore Sigils during JSON marshaling
	ChecksumAlgo crypt.HashType `json:"-"`
}

// Encode serializes a Trix struct into the .trix binary format.
func Encode(trix *Trix, magicNumber string) ([]byte, error) {
	if len(magicNumber) != 4 {
		return nil, ErrMagicNumberLength
	}

	// Calculate and add checksum if an algorithm is specified
	if trix.ChecksumAlgo != "" {
		checksum := crypt.NewService().Hash(trix.ChecksumAlgo, string(trix.Payload))
		trix.Header["checksum"] = checksum
		trix.Header["checksum_algo"] = string(trix.ChecksumAlgo)
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

	// Sanity check the header length to prevent massive allocations.
	if headerLength > MaxHeaderSize {
		return nil, ErrHeaderTooLarge
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

	// Verify checksum if it exists in the header
	if checksum, ok := header["checksum"].(string); ok {
		algo, ok := header["checksum_algo"].(string)
		if !ok {
			return nil, errors.New("trix: checksum algorithm not found in header")
		}
		expectedChecksum := crypt.NewService().Hash(crypt.HashType(algo), string(payload))
		if checksum != expectedChecksum {
			return nil, ErrChecksumMismatch
		}
	}

	return &Trix{
		Header:  header,
		Payload: payload,
	}, nil
}

// Pack applies the In method of all attached sigils to the payload.
func (t *Trix) Pack() error {
	for _, sigilName := range t.InSigils {
		sigil, err := enchantrix.NewSigil(sigilName)
		if err != nil {
			return err
		}
		if sigil == nil {
			return ErrNilSigil
		}
		t.Payload, err = sigil.In(t.Payload)
		if err != nil {
			return err
		}
	}
	return nil
}

// Unpack applies the Out method of all sigils in reverse order.
func (t *Trix) Unpack() error {
	sigilNames := t.OutSigils
	if len(sigilNames) == 0 {
		sigilNames = t.InSigils
	}
	for i := len(sigilNames) - 1; i >= 0; i-- {
		sigilName := sigilNames[i]
		sigil, err := enchantrix.NewSigil(sigilName)
		if err != nil {
			return err
		}
		if sigil == nil {
			return ErrNilSigil
		}
		t.Payload, err = sigil.Out(t.Payload)
		if err != nil {
			return err
		}
	}
	return nil
}
