// Example: Sigil transformation framework
//
// This example demonstrates the Sigil transformation framework, showing
// how to create transformation pipelines for encoding, compression, and
// hashing. Sigils can be chained together and reversed.
//
// Run with: go run examples/sigils/main.go
package main

import (
	"fmt"
	"log"

	"github.com/Snider/Enchantrix/pkg/enchantrix"
)

func main() {
	fmt.Println("--- Sigil Transformation Demo ---")

	// Original data
	data := []byte("Hello, Enchantrix! This is a demonstration of the Sigil framework.")
	fmt.Printf("Original data (%d bytes): %s\n\n", len(data), data)

	// 1. Single sigil transformation
	fmt.Println("1. Single Sigil (hex encoding):")
	hexSigil, _ := enchantrix.NewSigil("hex")
	hexEncoded, _ := hexSigil.In(data)
	fmt.Printf("   Hex encoded: %s\n", hexEncoded)
	hexDecoded, _ := hexSigil.Out(hexEncoded)
	fmt.Printf("   Hex decoded: %s\n\n", hexDecoded)

	// 2. Chained sigils using Transmute
	fmt.Println("2. Chained Sigils (gzip -> base64):")
	gzipSigil, _ := enchantrix.NewSigil("gzip")
	base64Sigil, _ := enchantrix.NewSigil("base64")

	// Apply chain: data -> gzip -> base64
	compressed, _ := gzipSigil.In(data)
	fmt.Printf("   After gzip (%d bytes)\n", len(compressed))

	result, _ := enchantrix.Transmute(data, []enchantrix.Sigil{gzipSigil, base64Sigil})
	fmt.Printf("   After gzip+base64 (%d bytes): %s...\n\n", len(result), result[:50])

	// 3. Reverse the chain
	fmt.Println("3. Reversing the Chain:")
	// Reverse order: base64.Out -> gzip.Out
	step1, _ := base64Sigil.Out(result)
	original, _ := gzipSigil.Out(step1)
	fmt.Printf("   Recovered: %s\n\n", original)

	// 4. Hash sigils (irreversible)
	fmt.Println("4. Hash Sigils (irreversible):")
	sha256Sigil, _ := enchantrix.NewSigil("sha256")
	hash, _ := sha256Sigil.In(data)
	fmt.Printf("   SHA-256 hash (%d bytes): %x\n", len(hash), hash)

	// Hash.Out is a no-op (returns input unchanged)
	passthrough, _ := sha256Sigil.Out(hash)
	fmt.Printf("   Hash.Out (passthrough): %x\n\n", passthrough)

	// 5. Symmetric sigil (reverse)
	fmt.Println("5. Symmetric Sigil (byte reversal):")
	reverseSigil, _ := enchantrix.NewSigil("reverse")
	reversed, _ := reverseSigil.In([]byte("Hello"))
	fmt.Printf("   'Hello' reversed: %s\n", reversed)
	// In and Out do the same thing for symmetric sigils
	unreversed, _ := reverseSigil.Out(reversed)
	fmt.Printf("   Reversed again: %s\n\n", unreversed)

	// 6. Available sigils
	fmt.Println("6. Available Sigils:")
	sigils := []string{
		"hex", "base64", "gzip", "reverse", "json", "json-indent",
		"md5", "sha1", "sha256", "sha512", "blake2b-256",
	}
	for _, name := range sigils {
		sigil, err := enchantrix.NewSigil(name)
		if err != nil {
			log.Printf("   - %s: ERROR\n", name)
		} else {
			_ = sigil // sigil is valid
			fmt.Printf("   - %s: OK\n", name)
		}
	}
}
