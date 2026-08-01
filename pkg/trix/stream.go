package trix

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
)

// PrefixSize is the size of the fixed framing that precedes the JSON header:
// magic (4) + version (1) + header length (4). RFC-0002 §3.1.
//
// Exported because it is the constant a caller needs to reason about payload
// offsets without decoding anything.
const PrefixSize = 4 + 1 + 4

var (
	// ErrNilWriter is returned when a streaming call is given no destination.
	ErrNilWriter = fmt.Errorf("trix: writer cannot be nil")
	// ErrNilReader is returned when a streaming call is given no source.
	ErrNilReader = fmt.Errorf("trix: reader cannot be nil")
)

// HeaderInfo describes a container's framing without touching its payload.
//
// PayloadBytes is best-effort: it is only populated when the reader can
// report its own size cheaply (an *os.File, *bytes.Reader, *strings.Reader
// or *io.SectionReader). A zero value means "unknown", never "empty".
type HeaderInfo struct {
	// Header is the decoded JSON header.
	Header map[string]interface{}
	// PayloadOffset is the byte offset of the first payload byte — the
	// value an mmap/pread of the binary tail starts from.
	PayloadOffset int64
	// PayloadBytes is the length of the payload in bytes, or 0 when the
	// reader cannot report its size.
	PayloadBytes int64
}

// EncodeStream writes an RFC-0002 container to w, copying payload straight
// through rather than buffering it. It returns the total number of bytes
// written to w — the full container length, which matches len(Encode(...))
// for the same header, magic and payload.
//
// The wire format is byte-for-byte identical to Encode: the two differ only
// in how the payload reaches the writer. Encode needs the whole payload
// resident as a []byte; EncodeStream needs a copy buffer, so a 128k-token
// State log costs the same allocation as a one-byte one.
//
// No transformation is applied to the payload — no sigil, no compression,
// no checksum, no encryption. The binary tail is exactly the bytes read
// from payload, so it can later become a zero-copy mmap of the source file.
// Callers wanting any of those apply them to the reader themselves.
//
//	f, _ := os.Create("session.kv")
//	src, _ := os.Open("session.mvlog")
//	n, err := trix.EncodeStream(map[string]interface{}{"kind": "state-kv"}, "KVST", src, f)
//
// A nil payload is treated as an empty payload, matching Encode's handling
// of a nil Trix.Payload.
func EncodeStream(header map[string]interface{}, magicNumber string, payload io.Reader, w io.Writer) (int64, error) {
	if len(magicNumber) != 4 {
		return 0, ErrMagicNumberLength
	}
	if w == nil {
		return 0, ErrNilWriter
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return 0, err
	}
	// Refuse to write a container Decode would refuse to read. Encode has
	// no such guard because it predates it; catching this on the way out
	// beats discovering it when the file is opened months later.
	if len(headerBytes) > MaxHeaderSize {
		return 0, ErrHeaderTooLarge
	}

	var prefix [PrefixSize]byte
	copy(prefix[:4], magicNumber)
	prefix[4] = byte(Version)
	binary.BigEndian.PutUint32(prefix[5:], uint32(len(headerBytes)))

	total := int64(0)
	n, err := w.Write(prefix[:])
	total += int64(n)
	if err != nil {
		return total, err
	}
	n, err = w.Write(headerBytes)
	total += int64(n)
	if err != nil {
		return total, err
	}
	if payload == nil {
		return total, nil
	}

	// io.Copy, never io.ReadAll — this is the whole point of the call.
	copied, err := io.Copy(w, payload)
	total += copied
	return total, err
}

// DecodeHeader reads and validates a container's framing from r and returns
// the decoded header plus a reader positioned at the first payload byte.
//
// Exactly PrefixSize+len(header) bytes are consumed — nothing is read ahead
// and nothing is buffered — so the returned reader (which is r itself) can be
// streamed, spliced or handed to an mmap-backed consumer without the payload
// ever being materialised.
//
//	header, payload, err := trix.DecodeHeader(f, "KVST")
//	if err != nil { return err }
//	_, err = io.Copy(dst, payload)
//
// A checksum recorded in the header is NOT verified: verification needs the
// whole payload, which is precisely what this path refuses to hold. Callers
// that want it should hash the payload stream as they consume it.
func DecodeHeader(r io.Reader, magicNumber string) (map[string]interface{}, io.Reader, error) {
	if len(magicNumber) != 4 {
		return nil, nil, ErrMagicNumberLength
	}
	if r == nil {
		return nil, nil, ErrNilReader
	}

	var prefix [PrefixSize]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, nil, err
	}
	headerLength, err := parsePrefix(prefix[:], magicNumber)
	if err != nil {
		return nil, nil, err
	}

	headerBytes := make([]byte, headerLength)
	if _, err := io.ReadFull(r, headerBytes); err != nil {
		return nil, nil, err
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, err
	}
	return header, r, nil
}

// DecodeStream reads a container from r and copies its payload to payload.
// It returns the decoded header and the number of payload bytes copied.
//
// The payload is written out byte-for-byte as stored; see DecodeHeader for
// the checksum caveat.
//
//	header, n, err := trix.DecodeStream(f, "KVST", out)
func DecodeStream(r io.Reader, magicNumber string, payload io.Writer) (map[string]interface{}, int64, error) {
	if payload == nil {
		return nil, 0, ErrNilWriter
	}
	header, rest, err := DecodeHeader(r, magicNumber)
	if err != nil {
		return nil, 0, err
	}
	n, err := io.Copy(payload, rest)
	return header, n, err
}

// ReadHeaderInfo reads a container's framing via random access and reports
// where the payload starts, without reading a single payload byte.
//
// This is what makes a zero-copy view of the binary tail possible: given the
// offset, a consumer can mmap or pread the payload region directly instead of
// streaming it through the process.
//
//	info, err := trix.ReadHeaderInfo(f, "KVST")
//	if err != nil { return err }
//	section := io.NewSectionReader(f, info.PayloadOffset, info.PayloadBytes)
func ReadHeaderInfo(r io.ReaderAt, magicNumber string) (HeaderInfo, error) {
	if len(magicNumber) != 4 {
		return HeaderInfo{}, ErrMagicNumberLength
	}
	if r == nil {
		return HeaderInfo{}, ErrNilReader
	}

	var prefix [PrefixSize]byte
	if _, err := r.ReadAt(prefix[:], 0); err != nil {
		return HeaderInfo{}, err
	}
	headerLength, err := parsePrefix(prefix[:], magicNumber)
	if err != nil {
		return HeaderInfo{}, err
	}

	headerBytes := make([]byte, headerLength)
	if headerLength > 0 {
		// A zero-length read is skipped: ReadAt implementations disagree
		// on whether an empty slice at EOF is an error.
		if _, err := r.ReadAt(headerBytes, PrefixSize); err != nil {
			return HeaderInfo{}, err
		}
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return HeaderInfo{}, err
	}

	info := HeaderInfo{
		Header:        header,
		PayloadOffset: PrefixSize + int64(headerLength),
	}
	if size, ok := readerSize(r); ok {
		if n := size - info.PayloadOffset; n > 0 {
			info.PayloadBytes = n
		}
	}
	return info, nil
}

// parsePrefix validates the fixed framing and returns the header length.
// Shared by every streaming entry point so magic, version and the header
// size limit are checked identically no matter how the bytes arrived.
func parsePrefix(prefix []byte, magicNumber string) (uint32, error) {
	if string(prefix[:4]) != magicNumber {
		return 0, fmt.Errorf("%w: expected %s, got %s", ErrInvalidMagicNumber, magicNumber, string(prefix[:4]))
	}
	if prefix[4] != Version {
		return 0, ErrInvalidVersion
	}
	headerLength := binary.BigEndian.Uint32(prefix[5:PrefixSize])
	// Same DoS guard Decode enforces — a hostile length must be rejected
	// before it is used to size an allocation.
	if headerLength > MaxHeaderSize {
		return 0, ErrHeaderTooLarge
	}
	return headerLength, nil
}

// readerSize reports the total size of r when it can be had for free.
//
// Seeking is deliberately not used: ReadHeaderInfo takes an io.ReaderAt so
// that it leaves the caller's file offset exactly where it found it, and a
// Seek(0, io.SeekEnd) probe would break that promise.
func readerSize(r io.ReaderAt) (int64, bool) {
	// *bytes.Reader, *strings.Reader and *io.SectionReader all report Size.
	if s, ok := r.(interface{ Size() int64 }); ok {
		return s.Size(), true
	}
	// *os.File.
	if s, ok := r.(interface{ Stat() (fs.FileInfo, error) }); ok {
		if info, err := s.Stat(); err == nil {
			return info.Size(), true
		}
	}
	return 0, false
}
