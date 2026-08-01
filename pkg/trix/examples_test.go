package trix_test

import (
	"bytes"
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

func ExampleEncodeStream() {
	// The payload is copied straight from reader to writer, so a container
	// holding a multi-gigabyte log costs the same memory as a tiny one.
	payload := bytes.NewReader([]byte("a very long state log"))

	var out bytes.Buffer
	n, err := trix.EncodeStream(map[string]interface{}{"kind": "state-kv"}, "KVST", payload, &out)
	if err != nil {
		log.Fatalf("EncodeStream failed: %v", err)
	}
	fmt.Printf("Container length: %d\n", n)
	// Output:
	// Container length: 49
}

func ExampleDecodeHeader() {
	var container bytes.Buffer
	if _, err := trix.EncodeStream(map[string]interface{}{"kind": "state-kv"}, "KVST", bytes.NewReader([]byte("binary tail")), &container); err != nil {
		log.Fatalf("EncodeStream failed: %v", err)
	}

	header, payload, err := trix.DecodeHeader(bytes.NewReader(container.Bytes()), "KVST")
	if err != nil {
		log.Fatalf("DecodeHeader failed: %v", err)
	}
	// payload is positioned at the first payload byte — stream it anywhere.
	var out bytes.Buffer
	if _, err := out.ReadFrom(payload); err != nil {
		log.Fatalf("copy failed: %v", err)
	}
	fmt.Printf("Header kind: %v\n", header["kind"])
	fmt.Printf("Payload: %s\n", out.String())
	// Output:
	// Header kind: state-kv
	// Payload: binary tail
}

func ExampleReadHeaderInfo() {
	var container bytes.Buffer
	if _, err := trix.EncodeStream(map[string]interface{}{"kind": "state-kv"}, "KVST", bytes.NewReader([]byte("binary tail")), &container); err != nil {
		log.Fatalf("EncodeStream failed: %v", err)
	}

	// No payload byte is read — the offset is what an mmap would start from.
	info, err := trix.ReadHeaderInfo(bytes.NewReader(container.Bytes()), "KVST")
	if err != nil {
		log.Fatalf("ReadHeaderInfo failed: %v", err)
	}
	fmt.Printf("Payload offset: %d\n", info.PayloadOffset)
	fmt.Printf("Payload bytes: %d\n", info.PayloadBytes)
	// Output:
	// Payload offset: 28
	// Payload bytes: 11
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
