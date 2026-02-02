package trix

import (
	"testing"
)

func BenchmarkPack(b *testing.B) {
	t := &Trix{
		Payload:  []byte("hello, world this is a test payload for benchmarking"),
		InSigils: []string{"base64", "gzip"},
	}
	originalPayload := t.Payload

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Reset payload before each run to ensure we're not re-packing packed data
		t.Payload = make([]byte, len(originalPayload))
		copy(t.Payload, originalPayload)
		if err := t.Pack(); err != nil {
			b.Fatal(err)
		}
	}
}
