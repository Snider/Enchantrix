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
