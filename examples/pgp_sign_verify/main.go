// Example: PGP digital signatures
//
// This example demonstrates creating and verifying PGP digital signatures.
// Signatures provide authenticity and integrity verification without
// encrypting the message content.
//
// Run with: go run examples/pgp_sign_verify/main.go
package main

import (
	"fmt"
	"log"

	"github.com/Snider/Enchantrix/pkg/crypt"
)

func main() {
	fmt.Println("--- PGP Signing & Verification Demo ---")
	cryptService := crypt.NewService()

	// 1. Generate PGP key pair
	fmt.Println("Generating PGP key pair...")
	publicKey, privateKey, err := cryptService.GeneratePGPKeyPair("test", "test@example.com", "test key")
	if err != nil {
		log.Fatalf("Failed to generate PGP key pair: %v", err)
	}
	fmt.Println("Key pair generated successfully.")

	// 2. Sign a message
	message := []byte("This is a message to be signed.")
	fmt.Printf("\nOriginal message: %s\n", message)
	signature, err := cryptService.SignPGP(privateKey, message)
	if err != nil {
		log.Fatalf("Failed to sign with PGP: %v", err)
	}
	fmt.Printf("Signature (armored):\n%s\n", signature)

	// 3. Verify the signature
	err = cryptService.VerifyPGP(publicKey, message, signature)
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}
	fmt.Println("Signature verified successfully!")
	fmt.Println()
}
