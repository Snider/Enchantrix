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
	Version = 2
)

var (
	ErrInvalidMagicNumber = errors.New("trix: invalid magic number")
	ErrInvalidVersion     = errors.New("trix: invalid version")
	ErrMagicNumberLength  = errors.New("trix: magic number must be 4 bytes long")
	ErrNilSigil           = errors.New("trix: sigil cannot be nil")
	ErrChecksumMismatch   = errors.New("trix: checksum mismatch")
	ErrInvalidHeaderLength = errors.New("trix: invalid header length")
)

// Trix represents the structure of a .trix file.
type Trix struct {
	Header       map[string]interface{}
	Payload      []byte
	InSigils     []string `json:"-"` // Ignore Sigils during JSON marshaling
	OutSigils    []string `json:"-"` // Ignore Sigils during JSON marshaling
	ChecksumAlgo crypt.HashType `json:"-"`
}

// EncodeTo serializes a Trix struct into the .trix binary format and writes it to an io.Writer.
func EncodeTo(trix *Trix, magicNumber string, w io.Writer) error {
	if len(magicNumber) != 4 {
		return ErrMagicNumberLength
	}

	// Calculate and add checksum if an algorithm is specified
	if trix.ChecksumAlgo != "" {
		checksum := crypt.NewService().Hash(trix.ChecksumAlgo, string(trix.Payload))
		trix.Header["checksum"] = checksum
		trix.Header["checksum_algo"] = string(trix.ChecksumAlgo)
	}

	headerBytes, err := json.Marshal(trix.Header)
	if err != nil {
		return err
	}
	headerLength := uint32(len(headerBytes))

	// Write Magic Number
	if _, err := io.WriteString(w, magicNumber); err != nil {
		return err
	}

	// Write Version
	if _, err := w.Write([]byte{byte(Version)}); err != nil {
		return err
	}

	// Write Header Length
	if err := binary.Write(w, binary.BigEndian, headerLength); err != nil {
		return err
	}

	// Write JSON Header
	if _, err := w.Write(headerBytes); err != nil {
		return err
	}

	// Write Payload
	if _, err := w.Write(trix.Payload); err != nil {
		return err
	}

	return nil
}

// Encode serializes a Trix struct into the .trix binary format.
func Encode(trix *Trix, magicNumber string) ([]byte, error) {
	var buf bytes.Buffer
	err := EncodeTo(trix, magicNumber, &buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodeFrom deserializes the .trix binary format from an io.Reader into a Trix struct.
func DecodeFrom(r io.Reader, magicNumber string) (*Trix, error) {
	if len(magicNumber) != 4 {
		return nil, ErrMagicNumberLength
	}

	// Read and Verify Magic Number
	magic := make([]byte, 4)
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, err
	}
	if string(magic) != magicNumber {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrInvalidMagicNumber, magicNumber, string(magic))
	}

	// Read and Verify Version
	versionByte := make([]byte, 1)
	if _, err := io.ReadFull(r, versionByte); err != nil {
		return nil, err
	}
	if versionByte[0] != Version {
		return nil, ErrInvalidVersion
	}

	// Read Header Length
	var headerLength uint32
	if err := binary.Read(r, binary.BigEndian, &headerLength); err != nil {
		return nil, err
	}

	// We can't implement the ErrInvalidHeaderLength check here because we don't know the total length of the stream.
	// The check is implicitly handled by io.ReadFull, which will return io.ErrUnexpectedEOF if the stream ends prematurely.

	// Read JSON Header
	headerBytes := make([]byte, headerLength)
	if _, err := io.ReadFull(r, headerBytes); err != nil {
		return nil, err
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}

	// Read Payload
	payload, err := io.ReadAll(r)
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

// Decode deserializes the .trix binary format into a Trix struct.
// Note: Sigils are not stored in the format and must be re-attached by the caller.
func Decode(data []byte, magicNumber string) (*Trix, error) {
	buf := bytes.NewReader(data)

	// We can perform the header length check here because we have the full byte slice.
	// We read the header length, check it, then pass the rest of the buffer to DecodeFrom.
	// This is a bit of a hack, but it's the only way to keep the check.
	// A better solution would be to have a separate DecodeBytes function.
	if len(data) > 9 { // 4 magic + 1 version + 4 header length
		headerLengthBytes := data[5:9]
		headerLength := binary.BigEndian.Uint32(headerLengthBytes)
		if int64(headerLength) > int64(len(data)-9) {
			return nil, ErrInvalidHeaderLength
		}
	}

	return DecodeFrom(buf, magicNumber)
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
