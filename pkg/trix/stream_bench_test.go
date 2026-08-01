package trix_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/Snider/Enchantrix/pkg/trix"
)

// benchPayloadSize is deliberately over the 64 MiB acceptance threshold —
// the size at which "just read it into a []byte" stops being acceptable for
// a State window.
const benchPayloadSize = 65 << 20

// Read B/op, not ns/op. The []byte benchmarks memcpy a payload that already
// exists in memory; the streaming ones pay for generating it a byte at a
// time inside patternReader, so the throughput columns are not comparable.
// Allocation is what these benchmarks are the receipt for.

// BenchmarkEncode_Large is the before number: the existing []byte API has to
// hold the whole payload and grow a buffer to hold the whole container.
func BenchmarkEncode_Large(b *testing.B) {
	payload := make([]byte, benchPayloadSize)
	for i := range payload {
		payload[i] = patternByte(int64(i))
	}
	header := map[string]interface{}{"kind": "state-kv"}

	b.SetBytes(benchPayloadSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := trix.Encode(&trix.Trix{Header: header, Payload: payload}, "KVST", nil)
		if err != nil {
			b.Fatal(err)
		}
		if len(out) < benchPayloadSize {
			b.Fatal("short container")
		}
	}
}

// BenchmarkEncodeStream_Large is the after number: allocation should be a
// copy buffer, not a copy of the payload.
func BenchmarkEncodeStream_Large(b *testing.B) {
	header := map[string]interface{}{"kind": "state-kv"}

	b.SetBytes(benchPayloadSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := &nullWriter{}
		if _, err := trix.EncodeStream(header, "KVST", &patternReader{size: benchPayloadSize}, w); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecode_Large is the before number for the read side: Decode
// io.ReadAll's the payload into a fresh []byte on every call.
func BenchmarkDecode_Large(b *testing.B) {
	payload := make([]byte, benchPayloadSize)
	for i := range payload {
		payload[i] = patternByte(int64(i))
	}
	container, err := trix.Encode(&trix.Trix{Header: map[string]interface{}{"kind": "state-kv"}, Payload: payload}, "KVST", nil)
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(benchPayloadSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := trix.Decode(container, "KVST", nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecodeStream_Large is the after number for the read side.
func BenchmarkDecodeStream_Large(b *testing.B) {
	var prefixBuf bytes.Buffer
	if _, err := trix.EncodeStream(map[string]interface{}{"kind": "state-kv"}, "KVST", nil, &prefixBuf); err != nil {
		b.Fatal(err)
	}
	prefix := prefixBuf.Bytes()

	b.SetBytes(benchPayloadSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := io.MultiReader(bytes.NewReader(prefix), &patternReader{size: benchPayloadSize})
		if _, _, err := trix.DecodeStream(r, "KVST", &nullWriter{}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReadHeaderInfo_Large proves the offset probe does not scale with
// the payload at all — it never touches it.
func BenchmarkReadHeaderInfo_Large(b *testing.B) {
	var container bytes.Buffer
	if _, err := trix.EncodeStream(map[string]interface{}{"kind": "state-kv"}, "KVST", &patternReader{size: benchPayloadSize}, &container); err != nil {
		b.Fatal(err)
	}
	r := bytes.NewReader(container.Bytes())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := trix.ReadHeaderInfo(r, "KVST"); err != nil {
			b.Fatal(err)
		}
	}
}
