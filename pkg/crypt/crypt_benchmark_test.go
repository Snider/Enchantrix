package crypt

import (
	"testing"
)

var service = NewService()

func BenchmarkHash(b *testing.B) {
	payload := "hello, world"
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		service.Hash(SHA256, payload)
	}
}

func BenchmarkGenerateRSAKeyPair(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := service.GenerateRSAKeyPair(2048)
		if err != nil {
			b.Fatal(err)
		}
	}
}
