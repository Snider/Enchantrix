// Example: Hashing with multiple algorithms
//
// This example demonstrates how to use the crypt service to compute hashes
// using various algorithms including the custom LTHN quasi-salted hash.
//
// Run with: go run examples/hash/main.go
package main

import (
	"fmt"

	"github.com/Snider/Enchantrix/pkg/crypt"
)

func main() {
	fmt.Println("--- Hashing Demo ---")
	cryptService := crypt.NewService()
	payload := "Enchantrix"

	hashTypes := []crypt.HashType{
		crypt.LTHN,
		crypt.MD5,
		crypt.SHA1,
		crypt.SHA256,
		crypt.SHA512,
	}

	fmt.Printf("Payload to hash: \"%s\"\n", payload)
	for _, hashType := range hashTypes {
		hash := cryptService.Hash(hashType, payload)
		fmt.Printf("  - %-6s: %s\n", hashType, hash)
	}
	fmt.Println()
}
