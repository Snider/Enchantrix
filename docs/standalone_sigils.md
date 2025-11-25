# Standalone Sigils

This example demonstrates how to use sigils independently to transform data.

## Available Sigils

The `enchantrix` package provides a wide variety of sigils for data transformation and hashing.

| Category | Sigils |
| :--- | :--- |
| **Encoding** | `hex`, `base64`, `reverse` |
| **Compression** | `gzip` |
| **Formatting** | `json`, `json-indent` |
| **Standard Hashes** | `md4`, `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512` |
| **Extended Hashes** | `ripemd160`, `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`, `sha512-224`, `sha512-256` |
| **Blake Hashes** | `blake2s-256`, `blake2b-256`, `blake2b-384`, `blake2b-512` |

## Usage Example

```go
package main

import (
	"fmt"
	"log"

	"github.com/Snider/Enchantrix/pkg/enchantrix"
)

func demoSigils() {
	fmt.Println("--- Standalone Sigil Demo ---")
	data := []byte(`{"message": "hello world"}`)
	fmt.Printf("Original data: %s\n", data)

	// A chain of sigils to apply
	sigils := []string{"gzip", "base64"}
	fmt.Printf("Applying sigil chain: %v\n", sigils)

	var transformedData = data
	for _, name := range sigils {
		s, err := enchantrix.NewSigil(name)
		if err != nil {
			log.Fatalf("Failed to create sigil %s: %v", name, err)
		}
		transformedData, err = s.In(transformedData)
		if err != nil {
			log.Fatalf("Failed to apply sigil %s 'In': %v", name, err)
		}
		fmt.Printf(" -> After '%s': %s\n", name, transformedData)
	}

	fmt.Println("\nReversing sigil chain...")
	// Reverse the transformations
	for i := len(sigils) - 1; i >= 0; i-- {
		name := sigils[i]
		s, err := enchantrix.NewSigil(name)
		if err != nil {
			log.Fatalf("Failed to create sigil %s: %v", name, err)
		}
		transformedData, err = s.Out(transformedData)
		if err != nil {
			log.Fatalf("Failed to apply sigil %s 'Out': %v", name, err)
		}
		fmt.Printf(" -> After '%s' Out: %s\n", name, transformedData)
	}

	if string(data) == string(transformedData) {
		fmt.Println("Success! Data returned to original state.")
	} else {
		fmt.Println("Failure! Data did not return to original state.")
	}
	fmt.Println()
}
```
