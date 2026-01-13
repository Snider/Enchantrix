// Example: PGP symmetric (passphrase-based) encryption
//
// This example demonstrates symmetric encryption using a passphrase
// instead of public/private key pairs. Useful when you need to share
// encrypted data with someone using a pre-shared password.
//
// Run with: go run examples/pgp_symmetric_encrypt/main.go
package main

import (
	"fmt"
	"log"

	"github.com/Snider/Enchantrix/pkg/crypt"
)

func main() {
	fmt.Println("--- PGP Symmetric Encryption Demo ---")
	cryptService := crypt.NewService()

	// 1. Encrypt a message with a passphrase
	message := []byte("This is a secret message for symmetric PGP encryption.")
	passphrase := []byte("my-secret-passphrase")
	fmt.Printf("\nOriginal message: %s\n", message)
	ciphertext, err := cryptService.SymmetricallyEncryptPGP(passphrase, message)
	if err != nil {
		log.Fatalf("Failed to encrypt with PGP: %v", err)
	}
	fmt.Printf("Encrypted ciphertext (armored):\n%s\n", ciphertext)
	fmt.Println()
}
