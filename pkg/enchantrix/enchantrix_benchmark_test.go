package enchantrix

import (
	"testing"
)

func BenchmarkTransmute(b *testing.B) {
	data := []byte("hello, world")
	sigils := []Sigil{
		&Base64Sigil{},
		&GzipSigil{},
		&HexSigil{},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := Transmute(data, sigils)
		if err != nil {
			b.Fatal(err)
		}
	}
}
