package trix_test

import (
	"fmt"
	"log"

	"github.com/Snider/Enchantrix/pkg/crypt"
	"github.com/Snider/Enchantrix/pkg/trix"
)

func ExampleEncode() {
	t := &trix.Trix{
		Header:  map[string]interface{}{"author": "Jules"},
		Payload: []byte("Hello, Trix!"),
	}
	encoded, err := trix.Encode(t, "TRIX", nil)
	if err != nil {
		log.Fatalf("Encode failed: %v", err)
	}
	fmt.Printf("Encoded data is not empty: %v\n", len(encoded) > 0)
	// Output:
	// Encoded data is not empty: true
}

func ExampleDecode() {
	t := &trix.Trix{
		Header:  map[string]interface{}{"author": "Jules"},
		Payload: []byte("Hello, Trix!"),
	}
	encoded, err := trix.Encode(t, "TRIX", nil)
	if err != nil {
		log.Fatalf("Encode failed: %v", err)
	}
	decoded, err := trix.Decode(encoded, "TRIX", nil)
	if err != nil {
		log.Fatalf("Decode failed: %v", err)
	}
	fmt.Printf("Decoded payload: %s\n", decoded.Payload)
	fmt.Printf("Decoded header: %v\n", decoded.Header)
	// Output:
	// Decoded payload: Hello, Trix!
	// Decoded header: map[author:Jules]
}

func ExampleTrix_Pack() {
	t := &trix.Trix{
		Payload:  []byte("secret message"),
		InSigils: []string{"base64", "reverse"},
	}
	err := t.Pack()
	if err != nil {
		log.Fatalf("Pack failed: %v", err)
	}
	fmt.Printf("Packed payload: %s\n", t.Payload)
	// Output:
	// Packed payload: =U2ZhN3cl1GI0VmcjV2c
}

func ExampleTrix_Unpack() {
	t := &trix.Trix{
		Payload:   []byte("=U2ZhN3cl1GI0VmcjV2c"),
		OutSigils: []string{"base64", "reverse"},
	}
	err := t.Unpack()
	if err != nil {
		log.Fatalf("Unpack failed: %v", err)
	}
	fmt.Printf("Unpacked payload: %s\n", t.Payload)
	// Output:
	// Unpacked payload: secret message
}

func ExampleTrix_Pack_checksum() {
	t := &trix.Trix{
		Header:       map[string]interface{}{},
		Payload:      []byte("secret message"),
		InSigils:     []string{"base64", "reverse"},
		ChecksumAlgo: crypt.SHA256,
	}
	encoded, err := trix.Encode(t, "TRIX", nil)
	if err != nil {
		log.Fatalf("Encode failed: %v", err)
	}
	decoded, err := trix.Decode(encoded, "TRIX", nil)
	if err != nil {
		log.Fatalf("Decode failed: %v", err)
	}
	fmt.Printf("Decoded payload: %s\n", decoded.Payload)
	fmt.Printf("Checksum verified: %v\n", decoded.Header["checksum"] != nil)
	// Output:
	// Decoded payload: secret message
	// Checksum verified: true
}
