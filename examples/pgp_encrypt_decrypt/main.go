package main

import (
	"fmt"
	"log"

	"github.com/Snider/Enchantrix/pkg/crypt"
)

func main() {
	fmt.Println("--- PGP Encryption & Decryption Demo ---")
	cryptService := crypt.NewService()

	// 1. Generate PGP key pair
	fmt.Println("Generating PGP key pair...")
	publicKey, privateKey, err := cryptService.GeneratePGPKeyPair("test", "test@example.com", "test key")
	if err != nil {
		log.Fatalf("Failed to generate PGP key pair: %v", err)
	}
	fmt.Println("Key pair generated successfully.")

	// 2. Encrypt a message
	message := []byte("This is a secret message for PGP.")
	fmt.Printf("\nOriginal message: %s\n", message)
	ciphertext, err := cryptService.EncryptPGP(publicKey, message)
	if err != nil {
		log.Fatalf("Failed to encrypt with PGP: %v", err)
	}
	fmt.Printf("Encrypted ciphertext (armored):\n%s\n", ciphertext)

	// 3. Decrypt the message
	decrypted, err := cryptService.DecryptPGP(privateKey, ciphertext)
	if err != nil {
		log.Fatalf("Failed to decrypt with PGP: %v", err)
	}
	fmt.Printf("Decrypted message: %s\n", decrypted)

	// 4. Verify
	if string(message) == string(decrypted) {
		fmt.Println("\nSuccess! PGP decrypted message matches the original.")
	} else {
		fmt.Println("\nFailure! PGP decrypted message does not match the original.")
	}
	fmt.Println()
}
