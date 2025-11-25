# PGP

This example demonstrates how to use the `crypt` service to perform PGP operations, including key generation, encryption, decryption, signing, and verification.

```go
package main

import (
	"fmt"
	"log"

	"github.com/Snider/Enchantrix/pkg/crypt"
)

func demoPGP() {
	fmt.Println("--- PGP Demo ---")
	cryptService := crypt.NewService()

	// 1. Generate PGP Key Pair
	fmt.Println("Generating PGP key pair...")
	publicKey, privateKey, err := cryptService.GeneratePGPKeyPair("Alice", "alice@example.com", "Demo Key")
	if err != nil {
		log.Fatalf("Failed to generate PGP key pair: %v", err)
	}
	fmt.Println("PGP Key pair generated successfully.")

	// 2. Asymmetric Encryption (Public Key Encryption)
	message := []byte("This is a secret message for PGP.")
	fmt.Printf("\nOriginal message: %s\n", message)

	encrypted, err := cryptService.EncryptPGP(publicKey, message)
	if err != nil {
		log.Fatalf("Failed to encrypt with PGP: %v", err)
	}
	fmt.Println("Message encrypted.")

	// 3. Decrypt with Private Key
	decrypted, err := cryptService.DecryptPGP(privateKey, encrypted)
	if err != nil {
		log.Fatalf("Failed to decrypt with PGP: %v", err)
	}
	fmt.Printf("Decrypted message: %s\n", decrypted)

	if string(message) == string(decrypted) {
		fmt.Println("Success! PGP decrypted message matches original.")
	} else {
		fmt.Println("Failure! PGP decrypted message does not match.")
	}

	// 4. Signing and Verification
	fmt.Println("\n--- PGP Signing Demo ---")
	signature, err := cryptService.SignPGP(privateKey, message)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}
	fmt.Println("Message signed.")

	err = cryptService.VerifyPGP(publicKey, message, signature)
	if err != nil {
		log.Fatalf("Failed to verify signature: %v", err)
	}
	fmt.Println("Success! Signature verified.")

	// 5. Symmetric Encryption (Passphrase)
	fmt.Println("\n--- PGP Symmetric Encryption Demo ---")
	passphrase := []byte("super-secure-passphrase")
	symEncrypted, err := cryptService.SymmetricallyEncryptPGP(passphrase, message)
	if err != nil {
		log.Fatalf("Failed to symmetrically encrypt: %v", err)
	}
	fmt.Println("Message symmetrically encrypted.")
    // Note: Decryption of symmetrically encrypted PGP messages requires a compatible reader
    // or usage of the underlying library's features, often handled automatically
    // if the decryptor prompts for a passphrase.
}
```
