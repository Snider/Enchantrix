# Standalone Sigils

This example demonstrates how to use sigils independently to transform data.

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
