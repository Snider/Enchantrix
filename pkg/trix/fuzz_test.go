package trix

import (
	"testing"
)

func FuzzDecode(f *testing.F) {
	// Seed with a valid encoded Trix object
	validTrix := &Trix{
		Header:  map[string]interface{}{"content_type": "text/plain"},
		Payload: []byte("hello world"),
	}
	validEncoded, _ := Encode(validTrix, "FUZZ")
	f.Add(validEncoded)

	// Seed with the corrupted header length from the ugly test
	var buf []byte
	buf = append(buf, []byte("UGLY")...)
	buf = append(buf, byte(Version))
	buf = append(buf, []byte{0, 0, 3, 232}...) // BigEndian representation of 1000
	buf = append(buf, []byte("{}")...)
	buf = append(buf, []byte("payload")...)
	f.Add(buf)

	// Seed with a short, invalid input
	f.Add([]byte("short"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// The fuzzer will generate random data here.
		// We just need to call our function and make sure it doesn't panic.
		// The fuzzer will report any crashes as failures.
		_, _ = Decode(data, "FUZZ")
	})
}
