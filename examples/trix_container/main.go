// Example: .trix container format
//
// This example demonstrates the .trix binary container format for packaging
// data with metadata and optional transformations. The format supports
// custom magic numbers, JSON headers, and sigil-based transformation pipelines.
//
// Run with: go run examples/trix_container/main.go
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/Snider/Enchantrix/pkg/crypt"
	"github.com/Snider/Enchantrix/pkg/trix"
)

func main() {
	fmt.Println("--- .trix Container Format Demo ---")

	// 1. Create a simple container
	fmt.Println("\n1. Simple Container:")
	simple := &trix.Trix{
		Header: map[string]interface{}{
			"content_type": "text/plain",
			"created_at":   time.Now().UTC().Format(time.RFC3339),
			"author":       "Enchantrix Demo",
		},
		Payload: []byte("Hello, this is the payload data!"),
	}

	encoded, err := trix.Encode(simple, "DEMO", nil)
	if err != nil {
		log.Fatalf("Failed to encode: %v", err)
	}
	fmt.Printf("   Encoded size: %d bytes\n", len(encoded))
	fmt.Printf("   Magic number: %s\n", encoded[:4])
	fmt.Printf("   Version: %d\n", encoded[4])

	// Decode it back
	decoded, err := trix.Decode(encoded, "DEMO", nil)
	if err != nil {
		log.Fatalf("Failed to decode: %v", err)
	}
	fmt.Printf("   Decoded payload: %s\n", decoded.Payload)
	fmt.Printf("   Header content_type: %s\n", decoded.Header["content_type"])

	// 2. Container with checksum verification
	fmt.Println("\n2. Container with Checksum:")
	withChecksum := &trix.Trix{
		Header: map[string]interface{}{
			"content_type": "application/octet-stream",
		},
		Payload:      []byte("Important data that needs integrity verification"),
		ChecksumAlgo: crypt.SHA256,
	}

	encodedWithChecksum, _ := trix.Encode(withChecksum, "CHKS", nil)
	fmt.Printf("   Encoded size: %d bytes\n", len(encodedWithChecksum))

	// Decode and verify checksum automatically
	decodedWithChecksum, err := trix.Decode(encodedWithChecksum, "CHKS", nil)
	if err != nil {
		log.Fatalf("Checksum verification failed: %v", err)
	}
	fmt.Printf("   Checksum verified! Algorithm: %s\n", decodedWithChecksum.Header["checksum_algo"])
	fmt.Printf("   Checksum value: %s...\n", decodedWithChecksum.Header["checksum"].(string)[:32])

	// 3. Container with sigil transformations
	fmt.Println("\n3. Container with Sigil Transformations:")
	withSigils := &trix.Trix{
		Header: map[string]interface{}{
			"content_type": "text/plain",
			"transformed":  true,
		},
		Payload:  []byte("This data will be compressed and encoded!"),
		InSigils: []string{"gzip", "base64"},
	}

	fmt.Printf("   Original payload size: %d bytes\n", len(withSigils.Payload))

	// Pack applies InSigils
	if err := withSigils.Pack(); err != nil {
		log.Fatalf("Pack failed: %v", err)
	}
	fmt.Printf("   After Pack (gzip+base64): %d bytes\n", len(withSigils.Payload))

	encodedWithSigils, _ := trix.Encode(withSigils, "TRNS", nil)
	fmt.Printf("   Final encoded size: %d bytes\n", len(encodedWithSigils))

	// Decode and unpack
	decodedWithSigils, _ := trix.Decode(encodedWithSigils, "TRNS", nil)
	decodedWithSigils.OutSigils = []string{"gzip", "base64"} // Must match InSigils

	if err := decodedWithSigils.Unpack(); err != nil {
		log.Fatalf("Unpack failed: %v", err)
	}
	fmt.Printf("   Unpacked payload: %s\n", decodedWithSigils.Payload)

	// 4. Custom magic numbers for different applications
	fmt.Println("\n4. Custom Magic Numbers:")
	apps := []struct {
		magic string
		desc  string
	}{
		{"CONF", "Configuration files"},
		{"LOGS", "Log archives"},
		{"KEYS", "Key storage"},
		{"MSGS", "Encrypted messages"},
	}
	for _, app := range apps {
		container := &trix.Trix{
			Header:  map[string]interface{}{"app": app.desc},
			Payload: []byte("sample"),
		}
		data, _ := trix.Encode(container, app.magic, nil)
		fmt.Printf("   %s: %s (%d bytes)\n", app.magic, app.desc, len(data))
	}

	fmt.Println("\nDone!")
}
