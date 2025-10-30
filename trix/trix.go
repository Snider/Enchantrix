package trix

import (
	"bytes"
	"errors"
	"io"
)

const (
	MagicNumber = "TRIX"
	Version     = 1
	Algorithm   = 1
)

var (
	ErrInvalidMagicNumber = errors.New("invalid magic number")
	ErrInvalidVersion     = errors.New("invalid version")
	ErrInvalidAlgorithm   = errors.New("invalid algorithm")
)

type Trix struct {
	MagicNumber [4]byte
	Version     byte
	Algorithm   byte
	Nonce       [24]byte
	Ciphertext  []byte
}

func Encode(trix *Trix) ([]byte, error) {
	buf := new(bytes.Buffer)

	if _, err := buf.Write(trix.MagicNumber[:]); err != nil {
		return nil, err
	}

	if err := buf.WriteByte(trix.Version); err != nil {
		return nil, err
	}

	if err := buf.WriteByte(trix.Algorithm); err != nil {
		return nil, err
	}

	if _, err := buf.Write(trix.Nonce[:]); err != nil {
		return nil, err
	}

	if _, err := buf.Write(trix.Ciphertext); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func Decode(data []byte) (*Trix, error) {
	buf := bytes.NewReader(data)

	var trix Trix

	if _, err := io.ReadFull(buf, trix.MagicNumber[:]); err != nil {
		return nil, err
	}

	if string(trix.MagicNumber[:]) != MagicNumber {
		return nil, ErrInvalidMagicNumber
	}

	version, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	trix.Version = version

	if trix.Version != Version {
		return nil, ErrInvalidVersion
	}

	algorithm, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	trix.Algorithm = algorithm

	if trix.Algorithm != Algorithm {
		return nil, ErrInvalidAlgorithm
	}

	if _, err := io.ReadFull(buf, trix.Nonce[:]); err != nil {
		return nil, err
	}

	trix.Ciphertext, err = io.ReadAll(buf)
	if err != nil {
		return nil, err
	}

	return &trix, nil
}
