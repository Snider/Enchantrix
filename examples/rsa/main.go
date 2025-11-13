package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/Snider/Enchantrix/pkg/crypt"
)

func main() {
	fmt.Println("--- RSA Demo ---")
	cryptService := crypt.NewService()

	// 1. Generate RSA key pair
	fmt.Println("Generating 2048-bit RSA key pair...")
	publicKey, privateKey, err := cryptService.GenerateRSAKeyPair(2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	fmt.Println("Key pair generated successfully.")

	// 2. Encrypt a message
	message := []byte("This is a secret message for RSA.")
	fmt.Printf("\nOriginal message: %s\n", message)
	ciphertext, err := cryptService.EncryptRSA(publicKey, message, nil)
	if err != nil {
		log.Fatalf("Failed to encrypt with RSA: %v", err)
	}
	fmt.Printf("Encrypted ciphertext (base64): %s\n", base64.StdEncoding.EncodeToString(ciphertext))

	// 3. Decrypt the message
	decrypted, err := cryptService.DecryptRSA(privateKey, ciphertext, nil)
	if err != nil {
		log.Fatalf("Failed to decrypt with RSA: %v", err)
	}
	fmt.Printf("Decrypted message: %s\n", decrypted)

	// 4. Verify
	if string(message) == string(decrypted) {
		fmt.Println("\nSuccess! RSA decrypted message matches the original.")
	} else {
		fmt.Println("\nFailure! RSA decrypted message does not match the original.")
	}
	fmt.Println()
}
