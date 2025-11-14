package enchantrix_test

import (
	"fmt"
	"log"

	"github.com/Snider/Enchantrix/pkg/enchantrix"
)

func ExampleTransmute() {
	data := []byte("Hello, World!")
	sigils := []enchantrix.Sigil{
		&enchantrix.ReverseSigil{},
		&enchantrix.HexSigil{},
	}
	transformed, err := enchantrix.Transmute(data, sigils)
	if err != nil {
		log.Fatalf("Transmute failed: %v", err)
	}
	fmt.Printf("Transformed data: %s\n", transformed)
	// Output:
	// Transformed data: 21646c726f57202c6f6c6c6548
}

func ExampleNewSigil() {
	sigil, err := enchantrix.NewSigil("base64")
	if err != nil {
		log.Fatalf("Failed to create sigil: %v", err)
	}
	data := []byte("Hello, World!")
	encoded, err := sigil.In(data)
	if err != nil {
		log.Fatalf("Sigil In failed: %v", err)
	}
	fmt.Printf("Encoded data: %s\n", encoded)
	decoded, err := sigil.Out(encoded)
	if err != nil {
		log.Fatalf("Sigil Out failed: %v", err)
	}
	fmt.Printf("Decoded data: %s\n", decoded)
	// Output:
	// Encoded data: SGVsbG8sIFdvcmxkIQ==
	// Decoded data: Hello, World!
}
