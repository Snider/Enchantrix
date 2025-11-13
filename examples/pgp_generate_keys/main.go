package main

import (
	"fmt"
	"log"

	"github.com/Snider/Enchantrix/pkg/crypt"
)

func main() {
	fmt.Println("--- PGP Key Generation Demo ---")
	cryptService := crypt.NewService()

	// 1. Generate PGP key pair
	fmt.Println("Generating PGP key pair...")
	publicKey, privateKey, err := cryptService.GeneratePGPKeyPair("test", "test@example.com", "test key")
	if err != nil {
		log.Fatalf("Failed to generate PGP key pair: %v", err)
	}
	fmt.Println("Key pair generated successfully.")
	fmt.Printf("\nPublic Key:\n%s\n", publicKey)
	fmt.Printf("\nPrivate Key:\n%s\n", privateKey)
}
