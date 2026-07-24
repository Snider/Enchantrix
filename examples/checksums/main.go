// Example: Checksum algorithms
//
// This example demonstrates Luhn and Fletcher checksum algorithms
// for data integrity verification.
//
// Run with: go run examples/checksums/main.go
package main

import (
	"fmt"

	"github.com/Snider/Enchantrix/pkg/crypt"
)

func main() {
	fmt.Println("--- Checksum Demo ---")
	cryptService := crypt.NewService()

	// Luhn
	luhnPayloadGood := "49927398716"
	luhnPayloadBad := "49927398717"
	fmt.Printf("Luhn Checksum:\n")
	fmt.Printf("  - Payload '%s' is valid: %v\n", luhnPayloadGood, cryptService.Luhn(luhnPayloadGood))
	fmt.Printf("  - Payload '%s' is valid: %v\n", luhnPayloadBad, cryptService.Luhn(luhnPayloadBad))

	// Fletcher
	fletcherPayload := "abcde"
	fmt.Printf("\nFletcher Checksums (Payload: \"%s\"):\n", fletcherPayload)
	fmt.Printf("  - Fletcher16: %d\n", cryptService.Fletcher16(fletcherPayload))
	fmt.Printf("  - Fletcher32: %d\n", cryptService.Fletcher32(fletcherPayload))
	fmt.Printf("  - Fletcher64: %d\n", cryptService.Fletcher64(fletcherPayload))
	fmt.Println()
}
