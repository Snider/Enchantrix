package trix_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Snider/Enchantrix/pkg/trix"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// patternByte is the deterministic content of the synthetic large payloads.
// It varies with absolute position so a chunk that arrives out of order, is
// duplicated or is dropped changes the bytes rather than sliding unnoticed.
func patternByte(offset int64) byte {
	return byte(offset*31 + 7)
}

// patternReader emits size bytes of patternByte content without ever holding
// more than one chunk — the large-payload tests must not themselves allocate
// what they are proving the container avoids.
type patternReader struct {
	size int64
	off  int64
}

func (p *patternReader) Read(b []byte) (int, error) {
	if p.off >= p.size {
		return 0, io.EOF
	}
	n := int64(len(b))
	if remaining := p.size - p.off; n > remaining {
		n = remaining
	}
	for i := int64(0); i < n; i++ {
		b[i] = patternByte(p.off + i)
	}
	p.off += n
	return int(n), nil
}

// patternVerifier checks a stream against patternByte as it arrives, so a
// multi-gigabyte payload can be proved byte-equal without being held.
type patternVerifier struct {
	off int64
	bad int64 // offset of the first mismatch, -1 when clean
}

func newPatternVerifier() *patternVerifier { return &patternVerifier{bad: -1} }

func (p *patternVerifier) Write(b []byte) (int, error) {
	for i := range b {
		if b[i] != patternByte(p.off+int64(i)) && p.bad < 0 {
			p.bad = p.off + int64(i)
		}
	}
	p.off += int64(len(b))
	return len(b), nil
}

// nullWriter counts bytes and nothing else. Deliberately does NOT implement
// io.ReaderFrom: io.Discard does, which would bypass the generic io.Copy path
// the allocation tests exist to measure.
type nullWriter struct{ n int64 }

func (w *nullWriter) Write(b []byte) (int, error) {
	w.n += int64(len(b))
	return len(b), nil
}

// totalAlloc reports the bytes allocated by f, measured from the runtime's
// cumulative counter. AllocsPerRun counts allocation *events*; the claim here
// is about allocated *bytes* not scaling with payload size, which is what
// TotalAlloc measures directly.
func totalAlloc(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestEncodeStream_Good round-trips a container through the streaming API and
// proves header and payload survive intact.
func TestEncodeStream_Good(t *testing.T) {
	header := map[string]interface{}{"kind": "state-kv", "token_count": float64(206)}
	payload := []byte("the binary tail, verbatim")

	var buf bytes.Buffer
	n, err := trix.EncodeStream(header, "KVST", bytes.NewReader(payload), &buf)
	require.NoError(t, err)
	assert.Equal(t, int64(buf.Len()), n, "returned count must be the container length")

	gotHeader, gotN, err := trix.DecodeStream(bytes.NewReader(buf.Bytes()), "KVST", io.Discard)
	require.NoError(t, err)
	assert.Equal(t, header, gotHeader)
	assert.Equal(t, int64(len(payload)), gotN)
}

// TestEncodeStream_ByteIdenticalToEncode_Good is the correctness anchor: for
// the same input the streaming writer must emit exactly the bytes the
// existing Encode emits. Any framing drift shows up here first.
func TestEncodeStream_ByteIdenticalToEncode_Good(t *testing.T) {
	large := make([]byte, 1<<20) // crosses many io.Copy buffer refills
	for i := range large {
		large[i] = patternByte(int64(i))
	}

	cases := []struct {
		name    string
		magic   string
		header  map[string]interface{}
		payload []byte
	}{
		{"TypicalHeader", "TRIX", map[string]interface{}{"content_type": "text/plain"}, []byte("hello")},
		{"CustomMagic", "KVST", map[string]interface{}{"kind": "state-kv"}, []byte("state log")},
		{"EmptyHeader", "TRIX", map[string]interface{}{}, []byte("payload")},
		{"NilHeader", "TRIX", nil, []byte("payload")},
		{"EmptyPayload", "TRIX", map[string]interface{}{"a": 1}, nil},
		{"BinaryPayload", "TRIX", map[string]interface{}{"a": 1}, []byte{0x00, 0xFF, 0x7F, 0x80, 0x00}},
		{"NestedHeader", "TRIX", map[string]interface{}{"z": 1, "a": map[string]interface{}{"b": []interface{}{1, 2}}}, []byte("x")},
		{"MebibytePayload", "KVST", map[string]interface{}{"kind": "state-kv"}, large},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			classic, err := trix.Encode(&trix.Trix{Header: tc.header, Payload: tc.payload}, tc.magic, nil)
			require.NoError(t, err)

			var streamed bytes.Buffer
			n, err := trix.EncodeStream(tc.header, tc.magic, bytes.NewReader(tc.payload), &streamed)
			require.NoError(t, err)

			assert.True(t, bytes.Equal(classic, streamed.Bytes()),
				"EncodeStream output differs from Encode output (%d vs %d bytes)", len(classic), streamed.Len())
			assert.Equal(t, int64(len(classic)), n)
		})
	}
}

// TestEncodeStream_NilPayload_Good treats a nil reader as an empty payload,
// matching Encode's handling of a nil Trix.Payload.
func TestEncodeStream_NilPayload_Good(t *testing.T) {
	var buf bytes.Buffer
	n, err := trix.EncodeStream(map[string]interface{}{"a": 1}, "TRIX", nil, &buf)
	require.NoError(t, err)

	classic, err := trix.Encode(&trix.Trix{Header: map[string]interface{}{"a": 1}}, "TRIX", nil)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(classic, buf.Bytes()))
	assert.Equal(t, int64(len(classic)), n)
}

// TestEncodeStream_Bad covers the well-formed-but-invalid inputs.
func TestEncodeStream_Bad(t *testing.T) {
	t.Run("MagicNumberLength", func(t *testing.T) {
		_, err := trix.EncodeStream(nil, "TOOLONG", bytes.NewReader(nil), &bytes.Buffer{})
		assert.ErrorIs(t, err, trix.ErrMagicNumberLength)
	})

	t.Run("NilWriter", func(t *testing.T) {
		_, err := trix.EncodeStream(nil, "TRIX", bytes.NewReader(nil), nil)
		assert.ErrorIs(t, err, trix.ErrNilWriter)
	})

	t.Run("UnmarshalableHeader", func(t *testing.T) {
		_, err := trix.EncodeStream(map[string]interface{}{"ch": make(chan int)}, "TRIX", nil, &bytes.Buffer{})
		assert.Error(t, err)
	})

	t.Run("HeaderTooLarge", func(t *testing.T) {
		// Encode would happily write this; the streaming path refuses to
		// produce a container Decode could never open.
		big := make([]byte, trix.MaxHeaderSize+10)
		for i := range big {
			big[i] = 'a'
		}
		_, err := trix.EncodeStream(map[string]interface{}{"large": string(big)}, "TRIX", nil, &bytes.Buffer{})
		assert.ErrorIs(t, err, trix.ErrHeaderTooLarge)
	})

	t.Run("WriteErrors", func(t *testing.T) {
		for i := 1; i <= 3; i++ {
			w := &failWriter{failOnCall: i}
			_, err := trix.EncodeStream(map[string]interface{}{"a": 1}, "TRIX", bytes.NewReader([]byte("payload")), w)
			assert.Error(t, err, "write call %d", i)
		}
	})

	t.Run("PayloadReadError", func(t *testing.T) {
		r := &failReader{failOnCall: 1, reader: bytes.NewReader([]byte("payload"))}
		_, err := trix.EncodeStream(map[string]interface{}{"a": 1}, "TRIX", r, &bytes.Buffer{})
		assert.Error(t, err)
	})
}

// TestDecodeHeader_Good proves the returned reader sits exactly on the first
// payload byte — the property that lets a caller stream or mmap the tail.
func TestDecodeHeader_Good(t *testing.T) {
	header := map[string]interface{}{"kind": "state-kv"}
	payload := []byte("0123456789abcdef")

	var buf bytes.Buffer
	_, err := trix.EncodeStream(header, "KVST", bytes.NewReader(payload), &buf)
	require.NoError(t, err)

	gotHeader, rest, err := trix.DecodeHeader(bytes.NewReader(buf.Bytes()), "KVST")
	require.NoError(t, err)
	assert.Equal(t, header, gotHeader)

	tail, err := io.ReadAll(rest)
	require.NoError(t, err)
	assert.Equal(t, payload, tail, "reader must be positioned at the payload, not past or before it")
}

// TestDecodeHeader_Bad covers rejected containers.
func TestDecodeHeader_Bad(t *testing.T) {
	good, err := trix.Encode(&trix.Trix{Header: map[string]interface{}{"a": 1}, Payload: []byte("p")}, "GOOD", nil)
	require.NoError(t, err)

	t.Run("MagicNumberLength", func(t *testing.T) {
		_, _, err := trix.DecodeHeader(bytes.NewReader(good), "SHORT")
		assert.ErrorIs(t, err, trix.ErrMagicNumberLength)
	})

	t.Run("NilReader", func(t *testing.T) {
		_, _, err := trix.DecodeHeader(nil, "GOOD")
		assert.ErrorIs(t, err, trix.ErrNilReader)
	})

	t.Run("MismatchedMagic", func(t *testing.T) {
		_, _, err := trix.DecodeHeader(bytes.NewReader(good), "BAD!")
		assert.ErrorIs(t, err, trix.ErrInvalidMagicNumber)
	})

	t.Run("InvalidVersion", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[4] = 99
		_, _, err := trix.DecodeHeader(bytes.NewReader(bad), "GOOD")
		assert.ErrorIs(t, err, trix.ErrInvalidVersion)
	})

	t.Run("HeaderTooLarge", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[5], bad[6], bad[7], bad[8] = 0xFF, 0xFF, 0xFF, 0xFF
		_, _, err := trix.DecodeHeader(bytes.NewReader(bad), "GOOD")
		assert.ErrorIs(t, err, trix.ErrHeaderTooLarge)
	})

	t.Run("TruncatedPrefix", func(t *testing.T) {
		_, _, err := trix.DecodeHeader(bytes.NewReader(good[:4]), "GOOD")
		assert.Error(t, err)
	})

	t.Run("TruncatedHeader", func(t *testing.T) {
		_, _, err := trix.DecodeHeader(bytes.NewReader(good[:trix.PrefixSize+1]), "GOOD")
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("MalformedHeaderJSON", func(t *testing.T) {
		var buf []byte
		buf = append(buf, []byte("GOOD")...)
		buf = append(buf, byte(trix.Version))
		buf = append(buf, 0, 0, 0, 1)
		buf = append(buf, '{')
		_, _, err := trix.DecodeHeader(bytes.NewReader(buf), "GOOD")
		assert.Error(t, err)
	})
}

// TestDecodeStream_Good round-trips a payload through a writer.
func TestDecodeStream_Good(t *testing.T) {
	payload := []byte("streamed straight back out")
	var container bytes.Buffer
	_, err := trix.EncodeStream(map[string]interface{}{"a": 1}, "TRIX", bytes.NewReader(payload), &container)
	require.NoError(t, err)

	var out bytes.Buffer
	header, n, err := trix.DecodeStream(bytes.NewReader(container.Bytes()), "TRIX", &out)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"a": float64(1)}, header)
	assert.Equal(t, int64(len(payload)), n)
	assert.Equal(t, payload, out.Bytes())
}

// TestDecodeStream_Bad covers the rejected inputs unique to DecodeStream.
func TestDecodeStream_Bad(t *testing.T) {
	t.Run("NilWriter", func(t *testing.T) {
		_, _, err := trix.DecodeStream(bytes.NewReader(nil), "TRIX", nil)
		assert.ErrorIs(t, err, trix.ErrNilWriter)
	})

	t.Run("CorruptContainer", func(t *testing.T) {
		_, _, err := trix.DecodeStream(bytes.NewReader([]byte("not a container")), "TRIX", &bytes.Buffer{})
		assert.Error(t, err)
	})

	t.Run("PayloadWriteError", func(t *testing.T) {
		var container bytes.Buffer
		_, err := trix.EncodeStream(map[string]interface{}{"a": 1}, "TRIX", bytes.NewReader([]byte("payload")), &container)
		require.NoError(t, err)

		// failWriter fails on its first call, which the payload copy makes.
		_, _, err = trix.DecodeStream(bytes.NewReader(container.Bytes()), "TRIX", &failWriter{failOnCall: 1})
		assert.Error(t, err)
	})
}

// TestReadHeaderInfo_Good proves the reported offset is the exact first
// payload byte, for both an in-memory reader and a real file.
func TestReadHeaderInfo_Good(t *testing.T) {
	header := map[string]interface{}{"kind": "state-kv", "id": "session-1-fold-1"}
	payload := []byte("the binary tail nobody should have to read")

	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	wantOffset := int64(trix.PrefixSize + len(headerJSON))

	var container bytes.Buffer
	_, err = trix.EncodeStream(header, "KVST", bytes.NewReader(payload), &container)
	require.NoError(t, err)

	t.Run("BytesReader", func(t *testing.T) {
		info, err := trix.ReadHeaderInfo(bytes.NewReader(container.Bytes()), "KVST")
		require.NoError(t, err)
		assert.Equal(t, header, info.Header)
		assert.Equal(t, wantOffset, info.PayloadOffset)
		assert.Equal(t, int64(len(payload)), info.PayloadBytes)
		assert.Equal(t, payload, container.Bytes()[info.PayloadOffset:])
	})

	t.Run("OsFile", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "session.kv")
		require.NoError(t, os.WriteFile(path, container.Bytes(), 0o600))

		f, err := os.Open(path)
		require.NoError(t, err)
		defer func() { _ = f.Close() }()

		// Consume a byte first: ReadHeaderInfo must not disturb the handle's
		// own offset, or a caller interleaving reads would silently skip data.
		one := make([]byte, 1)
		_, err = f.Read(one)
		require.NoError(t, err)

		info, err := trix.ReadHeaderInfo(f, "KVST")
		require.NoError(t, err)
		assert.Equal(t, header, info.Header)
		assert.Equal(t, wantOffset, info.PayloadOffset)
		assert.Equal(t, int64(len(payload)), info.PayloadBytes)

		next := make([]byte, 1)
		_, err = f.Read(next)
		require.NoError(t, err)
		assert.Equal(t, container.Bytes()[1], next[0], "ReadHeaderInfo moved the file offset")

		// The reported offset addresses the payload directly.
		tail := make([]byte, info.PayloadBytes)
		_, err = f.ReadAt(tail, info.PayloadOffset)
		require.NoError(t, err)
		assert.Equal(t, payload, tail)
	})

	t.Run("UnsizedReader", func(t *testing.T) {
		// An io.ReaderAt with no cheap size still reports a valid offset;
		// PayloadBytes is documented as best-effort.
		info, err := trix.ReadHeaderInfo(readerAtOnly{bytes.NewReader(container.Bytes())}, "KVST")
		require.NoError(t, err)
		assert.Equal(t, wantOffset, info.PayloadOffset)
		assert.Equal(t, int64(0), info.PayloadBytes)
	})
}

// readerAtOnly hides Size/Stat so readerSize has nothing to work with.
type readerAtOnly struct{ r io.ReaderAt }

func (r readerAtOnly) ReadAt(p []byte, off int64) (int, error) { return r.r.ReadAt(p, off) }

// TestReadHeaderInfo_Bad covers rejected containers.
func TestReadHeaderInfo_Bad(t *testing.T) {
	good, err := trix.Encode(&trix.Trix{Header: map[string]interface{}{"a": 1}, Payload: []byte("p")}, "GOOD", nil)
	require.NoError(t, err)

	t.Run("MagicNumberLength", func(t *testing.T) {
		_, err := trix.ReadHeaderInfo(bytes.NewReader(good), "SHORT")
		assert.ErrorIs(t, err, trix.ErrMagicNumberLength)
	})

	t.Run("NilReader", func(t *testing.T) {
		_, err := trix.ReadHeaderInfo(nil, "GOOD")
		assert.ErrorIs(t, err, trix.ErrNilReader)
	})

	t.Run("MismatchedMagic", func(t *testing.T) {
		_, err := trix.ReadHeaderInfo(bytes.NewReader(good), "BAD!")
		assert.ErrorIs(t, err, trix.ErrInvalidMagicNumber)
	})

	t.Run("InvalidVersion", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[4] = 99
		_, err := trix.ReadHeaderInfo(bytes.NewReader(bad), "GOOD")
		assert.ErrorIs(t, err, trix.ErrInvalidVersion)
	})

	t.Run("HeaderTooLarge", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[5], bad[6], bad[7], bad[8] = 0xFF, 0xFF, 0xFF, 0xFF
		_, err := trix.ReadHeaderInfo(bytes.NewReader(bad), "GOOD")
		assert.ErrorIs(t, err, trix.ErrHeaderTooLarge)
	})

	t.Run("TruncatedPrefix", func(t *testing.T) {
		_, err := trix.ReadHeaderInfo(bytes.NewReader(good[:4]), "GOOD")
		assert.Error(t, err)
	})

	t.Run("TruncatedHeader", func(t *testing.T) {
		_, err := trix.ReadHeaderInfo(bytes.NewReader(good[:trix.PrefixSize+1]), "GOOD")
		assert.Error(t, err)
	})
}

// TestStream_NoImplicitTransforms_Good is the P1 guarantee: the binary tail
// is the input bytes and nothing else, and the header gains no keys the
// caller did not put there. A .kv file has to stay mmap-able.
func TestStream_NoImplicitTransforms_Good(t *testing.T) {
	// Bytes chosen to look like something a "helpful" transform would touch:
	// gzip magic, valid base64, a JSON fragment, NULs.
	payload := []byte{0x1F, 0x8B, 0x08, 0x00, '{', '"', 'a', '"', ':', '1', '}', 0x00, 'Z', 'm', '9', 'v'}
	header := map[string]interface{}{"kind": "state-kv"}

	var container bytes.Buffer
	_, err := trix.EncodeStream(header, "KVST", bytes.NewReader(payload), &container)
	require.NoError(t, err)

	info, err := trix.ReadHeaderInfo(bytes.NewReader(container.Bytes()), "KVST")
	require.NoError(t, err)

	// The container's tail is the input, byte for byte, at the stated offset.
	assert.Equal(t, payload, container.Bytes()[info.PayloadOffset:])
	assert.Equal(t, int64(len(payload)), info.PayloadBytes)

	// The header carries exactly what the caller supplied.
	assert.Equal(t, header, info.Header)
	for _, key := range []string{"checksum", "checksum_algo", "compression", "sigils", "encrypted", "encryption_algorithm"} {
		_, present := info.Header[key]
		assert.False(t, present, "streaming encode added %q to the header", key)
	}

	// And the round trip returns the same bytes.
	var out bytes.Buffer
	_, _, err = trix.DecodeStream(bytes.NewReader(container.Bytes()), "KVST", &out)
	require.NoError(t, err)
	assert.Equal(t, payload, out.Bytes())
}

// TestStream_LargePayload_BoundedAllocations is the receipt the whole change
// exists for: encoding and decoding a >64 MiB payload must allocate the same
// as a 1 MiB one. The 64→128 MiB delta is the measurement — if the payload
// were being buffered anywhere, it would grow by ~64 MiB.
func TestStream_LargePayload_BoundedAllocations(t *testing.T) {
	if testing.Short() {
		t.Skip("large payload test skipped in -short mode")
	}

	const (
		sizeSmall = 1 << 20  // 1 MiB
		size64    = 65 << 20 // 65 MiB — over the acceptance threshold
		size128   = 130 << 20
		// One io.Copy buffer (32 KiB) plus header/prefix churn is the
		// honest ceiling; 1 MiB leaves room for GC bookkeeping noise
		// while being ~1.5% of the payload growth it must not track.
		tolerance = 1 << 20
	)

	// Assertions live outside the measured region — testify's reflection
	// allocates, and it would land in the numbers being reported.
	encodeAlloc := func(size int64) uint64 {
		var (
			w   nullWriter
			n   int64
			err error
		)
		alloc := totalAlloc(func() {
			n, err = trix.EncodeStream(map[string]interface{}{"kind": "state-kv"}, "KVST", &patternReader{size: size}, &w)
		})
		require.NoError(t, err)
		require.Equal(t, w.n, n)
		return alloc
	}

	small := encodeAlloc(sizeSmall)
	big := encodeAlloc(size64)
	bigger := encodeAlloc(size128)
	t.Logf("EncodeStream allocated bytes: 1MiB=%d 65MiB=%d 130MiB=%d", small, big, bigger)

	assert.Less(t, big, uint64(tolerance),
		"encoding 65 MiB allocated %d bytes — the payload is being buffered", big)
	assert.Less(t, absDiff(bigger, big), uint64(tolerance),
		"allocation tracks payload size: 65 MiB=%d, 130 MiB=%d", big, bigger)

	// Decode side: same measurement, and the payload is verified byte-for-byte
	// on the way past so "bounded" cannot be bought by dropping data.
	var container bytes.Buffer
	container.Grow(trix.PrefixSize + 64)
	_, err := trix.EncodeStream(map[string]interface{}{"kind": "state-kv"}, "KVST", nil, &container)
	require.NoError(t, err)
	prefix := append([]byte(nil), container.Bytes()...)

	decodeAlloc := func(size int64) uint64 {
		var (
			verifier = newPatternVerifier()
			n        int64
			err      error
		)
		alloc := totalAlloc(func() {
			r := io.MultiReader(bytes.NewReader(prefix), &patternReader{size: size})
			_, n, err = trix.DecodeStream(r, "KVST", verifier)
		})
		require.NoError(t, err)
		require.Equal(t, size, n)
		require.Equal(t, int64(-1), verifier.bad, "payload byte mismatch at offset %d", verifier.bad)
		require.Equal(t, size, verifier.off)
		return alloc
	}

	dBig := decodeAlloc(size64)
	dBigger := decodeAlloc(size128)
	t.Logf("DecodeStream allocated bytes: 65MiB=%d 130MiB=%d", dBig, dBigger)

	assert.Less(t, dBig, uint64(tolerance),
		"decoding 65 MiB allocated %d bytes — the payload is being buffered", dBig)
	assert.Less(t, absDiff(dBigger, dBig), uint64(tolerance),
		"allocation tracks payload size: 65 MiB=%d, 130 MiB=%d", dBig, dBigger)
}

func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// TestStream_LargePayload_RoundTripEquality proves a >64 MiB payload survives
// the container unchanged, without either side holding it in memory.
func TestStream_LargePayload_RoundTripEquality(t *testing.T) {
	if testing.Short() {
		t.Skip("large payload test skipped in -short mode")
	}

	const size = 65 << 20 // 65 MiB
	path := filepath.Join(t.TempDir(), "large.kv")

	f, err := os.Create(path)
	require.NoError(t, err)
	written, err := trix.EncodeStream(map[string]interface{}{"kind": "state-kv"}, "KVST", &patternReader{size: size}, f)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	stat, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, stat.Size(), written)

	in, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = in.Close() }()

	info, err := trix.ReadHeaderInfo(in, "KVST")
	require.NoError(t, err)
	assert.Equal(t, int64(size), info.PayloadBytes)
	assert.Equal(t, written-int64(size), info.PayloadOffset)

	verifier := newPatternVerifier()
	_, n, err := trix.DecodeStream(in, "KVST", verifier)
	require.NoError(t, err)
	assert.Equal(t, int64(size), n)
	assert.Equal(t, int64(-1), verifier.bad, "payload differs from input at offset %d", verifier.bad)
	assert.Equal(t, int64(size), verifier.off)
}
