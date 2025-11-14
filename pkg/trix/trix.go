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
	// Version is the current version of the .trix file format.
	Version = 2
	// MaxHeaderSize is the maximum allowed size for the header.
	MaxHeaderSize = 16 * 1024 * 1024 // 16 MB
)

var (
	// ErrInvalidMagicNumber is returned when the magic number is incorrect.
	ErrInvalidMagicNumber = errors.New("trix: invalid magic number")
	// ErrInvalidVersion is returned when the version is incorrect.
	ErrInvalidVersion = errors.New("trix: invalid version")
	// ErrMagicNumberLength is returned when the magic number is not 4 bytes long.
	ErrMagicNumberLength = errors.New("trix: magic number must be 4 bytes long")
	// ErrNilSigil is returned when a sigil is nil.
	ErrNilSigil = errors.New("trix: sigil cannot be nil")
	// ErrChecksumMismatch is returned when the checksum does not match.
	ErrChecksumMismatch = errors.New("trix: checksum mismatch")
	// ErrHeaderTooLarge is returned when the header size exceeds the maximum allowed.
	ErrHeaderTooLarge = errors.New("trix: header size exceeds maximum allowed")
)

// Trix represents the structure of a .trix file.
// It contains a header, a payload, and optional sigils for data transformation.
type Trix struct {
	Header       map[string]interface{}
	Payload      []byte
	InSigils     []string       `json:"-"` // Ignore Sigils during JSON marshaling
	OutSigils    []string       `json:"-"` // Ignore Sigils during JSON marshaling
	ChecksumAlgo crypt.HashType `json:"-"`
}

// Encode serializes a Trix struct into the .trix binary format.
// It returns the encoded data as a byte slice.
func Encode(trix *Trix, magicNumber string, w io.Writer) ([]byte, error) {
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

	// If no writer is provided, use an internal buffer.
	// This maintains the original function signature's behavior of returning the byte slice.
	var buf *bytes.Buffer
	writer := w
	if writer == nil {
		buf = new(bytes.Buffer)
		writer = buf
	}

	// Write Magic Number
	if _, err := io.WriteString(writer, magicNumber); err != nil {
		return nil, err
	}

	// Write Version
	if _, err := writer.Write([]byte{byte(Version)}); err != nil {
		return nil, err
	}

	// Write Header Length
	if err := binary.Write(writer, binary.BigEndian, headerLength); err != nil {
		return nil, err
	}

	// Write JSON Header
	if _, err := writer.Write(headerBytes); err != nil {
		return nil, err
	}

	// Write Payload
	if _, err := writer.Write(trix.Payload); err != nil {
		return nil, err
	}

	// If we used our internal buffer, return its bytes.
	if buf != nil {
		return buf.Bytes(), nil
	}

	// If an external writer was used, we can't return the bytes.
	// The caller is responsible for the writer.
	return nil, nil
}

// Decode deserializes the .trix binary format into a Trix struct.
// It returns the decoded Trix struct.
// Note: Sigils are not stored in the format and must be re-attached by the caller.
func Decode(data []byte, magicNumber string, r io.Reader) (*Trix, error) {
	if len(magicNumber) != 4 {
		return nil, ErrMagicNumberLength
	}

	var reader io.Reader
	if r != nil {
		reader = r
	} else {
		reader = bytes.NewReader(data)
	}

	// Read and Verify Magic Number
	magic := make([]byte, 4)
	if _, err := io.ReadFull(reader, magic); err != nil {
		return nil, err
	}
	if string(magic) != magicNumber {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrInvalidMagicNumber, magicNumber, string(magic))
	}

	// Read and Verify Version
	versionByte := make([]byte, 1)
	if _, err := io.ReadFull(reader, versionByte); err != nil {
		return nil, err
	}
	if versionByte[0] != Version {
		return nil, ErrInvalidVersion
	}

	// Read Header Length
	var headerLength uint32
	if err := binary.Read(reader, binary.BigEndian, &headerLength); err != nil {
		return nil, err
	}

	// Sanity check the header length to prevent massive allocations.
	if headerLength > MaxHeaderSize {
		return nil, ErrHeaderTooLarge
	}

	// Read JSON Header
	headerBytes := make([]byte, headerLength)
	if _, err := io.ReadFull(reader, headerBytes); err != nil {
		return nil, err
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}

	// Read Payload
	payload, err := io.ReadAll(reader)
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
// It modifies the Trix struct in place.
func (t *Trix) Pack() error {
	for _, sigilName := range t.InSigils {
		sigil, err := enchantrix.NewSigil(sigilName)
		if err != nil {
			return err
		}
		t.Payload, err = sigil.In(t.Payload)
		if err != nil {
			return err
		}
	}
	return nil
}

// Unpack applies the Out method of all sigils in reverse order.
// It modifies the Trix struct in place.
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
		t.Payload, err = sigil.Out(t.Payload)
		if err != nil {
			return err
		}
	}
	return nil
}
