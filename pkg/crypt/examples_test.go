package crypt_test

import (
	"fmt"
	"log"

	"github.com/Snider/Enchantrix/pkg/crypt"
)

func ExampleService_Hash() {
	cryptService := crypt.NewService()
	payload := "Enchantrix"

	hashTypes := []crypt.HashType{
		crypt.LTHN,
		crypt.MD5,
		crypt.SHA1,
		crypt.SHA256,
		crypt.SHA512,
	}

	fmt.Printf("Payload to hash: \"%s\"\n", payload)
	for _, hashType := range hashTypes {
		hash := cryptService.Hash(hashType, payload)
		fmt.Printf("  - %-6s: %s\n", hashType, hash)
	}
	// Output:
	// Payload to hash: "Enchantrix"
	//   - lthn  : 331f24f86375846ac8d0d06cfb80cb2877e8900548a88d4ac8d39177cd854dab
	//   - md5   : 7c54903a10f058a93fd1f21ea802cb27
	//   - sha1  : 399f776c4b97e558a2c4f319b223dd481c6d43f1
	//   - sha256: 2ae653f74554abfdb2343013925f5184a0f05e4c2e0c3881448fc80caeb667c2
	//   - sha512: 9638018a9720b5d83fba7f3899e4ba5ab78018781f9c600f0c0738ff8ccf1ea54e1c783ee8778542b70aa26283d87ce88784b2df5697322546d3b8029c4b6797
}

func ExampleService_Luhn() {
	cryptService := crypt.NewService()
	luhnPayloadGood := "49927398716"
	luhnPayloadBad := "49927398717"
	fmt.Printf("Luhn Checksum:\n")
	fmt.Printf("  - Payload '%s' is valid: %v\n", luhnPayloadGood, cryptService.Luhn(luhnPayloadGood))
	fmt.Printf("  - Payload '%s' is valid: %v\n", luhnPayloadBad, cryptService.Luhn(luhnPayloadBad))
	// Output:
	// Luhn Checksum:
	//   - Payload '49927398716' is valid: true
	//   - Payload '49927398717' is valid: false
}

func ExampleService_Fletcher16() {
	cryptService := crypt.NewService()
	fletcherPayload := "abcde"
	fmt.Printf("Fletcher16 Checksum (Payload: \"%s\"): %d\n", fletcherPayload, cryptService.Fletcher16(fletcherPayload))
	// Output:
	// Fletcher16 Checksum (Payload: "abcde"): 51440
}

func ExampleService_Fletcher32() {
	cryptService := crypt.NewService()
	fletcherPayload := "abcde"
	fmt.Printf("Fletcher32 Checksum (Payload: \"%s\"): %d\n", fletcherPayload, cryptService.Fletcher32(fletcherPayload))
	// Output:
	// Fletcher32 Checksum (Payload: "abcde"): 4031760169
}

func ExampleService_Fletcher64() {
	cryptService := crypt.NewService()
	fletcherPayload := "abcde"
	fmt.Printf("Fletcher64 Checksum (Payload: \"%s\"): %d\n", fletcherPayload, cryptService.Fletcher64(fletcherPayload))
	// Output:
	// Fletcher64 Checksum (Payload: "abcde"): 14467467625952928454
}

func ExampleService_GeneratePGPKeyPair() {
	cryptService := crypt.NewService()
	publicKey, privateKey, err := cryptService.GeneratePGPKeyPair("test", "test@example.com", "test key")
	if err != nil {
		log.Fatalf("Failed to generate PGP key pair: %v", err)
	}
	fmt.Printf("PGP public key is not empty: %v\n", len(publicKey) > 0)
	fmt.Printf("PGP private key is not empty: %v\n", len(privateKey) > 0)
	// Output:
	// PGP public key is not empty: true
	// PGP private key is not empty: true
}

func ExampleService_EncryptPGP() {
	cryptService := crypt.NewService()
	publicKey, _, err := cryptService.GeneratePGPKeyPair("test", "test@example.com", "test key")
	if err != nil {
		log.Fatalf("Failed to generate PGP key pair: %v", err)
	}
	message := []byte("This is a secret message for PGP.")
	ciphertext, err := cryptService.EncryptPGP(publicKey, message)
	if err != nil {
		log.Fatalf("Failed to encrypt with PGP: %v", err)
	}
	fmt.Printf("PGP ciphertext is not empty: %v\n", len(ciphertext) > 0)
	// Output:
	// PGP ciphertext is not empty: true
}

func ExampleService_DecryptPGP() {
	cryptService := crypt.NewService()
	publicKey, privateKey, err := cryptService.GeneratePGPKeyPair("test", "test@example.com", "test key")
	if err != nil {
		log.Fatalf("Failed to generate PGP key pair: %v", err)
	}
	message := []byte("This is a secret message for PGP.")
	ciphertext, err := cryptService.EncryptPGP(publicKey, message)
	if err != nil {
		log.Fatalf("Failed to encrypt with PGP: %v", err)
	}
	decrypted, err := cryptService.DecryptPGP(privateKey, ciphertext)
	if err != nil {
		log.Fatalf("Failed to decrypt with PGP: %v", err)
	}
	fmt.Printf("Decrypted message: %s\n", decrypted)
	// Output:
	// Decrypted message: This is a secret message for PGP.
}

func ExampleService_SignPGP() {
	cryptService := crypt.NewService()
	_, privateKey, err := cryptService.GeneratePGPKeyPair("test", "test@example.com", "test key")
	if err != nil {
		log.Fatalf("Failed to generate PGP key pair: %v", err)
	}
	message := []byte("This is a message to be signed.")
	signature, err := cryptService.SignPGP(privateKey, message)
	if err != nil {
		log.Fatalf("Failed to sign with PGP: %v", err)
	}
	fmt.Printf("PGP signature is not empty: %v\n", len(signature) > 0)
	// Output:
	// PGP signature is not empty: true
}

func ExampleService_VerifyPGP() {
	cryptService := crypt.NewService()
	publicKey, privateKey, err := cryptService.GeneratePGPKeyPair("test", "test@example.com", "test key")
	if err != nil {
		log.Fatalf("Failed to generate PGP key pair: %v", err)
	}
	message := []byte("This is a message to be signed.")
	signature, err := cryptService.SignPGP(privateKey, message)
	if err != nil {
		log.Fatalf("Failed to sign with PGP: %v", err)
	}
	err = cryptService.VerifyPGP(publicKey, message, signature)
	if err != nil {
		fmt.Println("PGP signature verification failed.")
	} else {
		fmt.Println("PGP signature verified successfully.")
	}
	// Output:
	// PGP signature verified successfully.
}

func ExampleService_SymmetricallyEncryptPGP() {
	cryptService := crypt.NewService()
	passphrase := []byte("my secret passphrase")
	message := []byte("This is a symmetric secret.")
	ciphertext, err := cryptService.SymmetricallyEncryptPGP(passphrase, message)
	if err != nil {
		log.Fatalf("Failed to symmetrically encrypt with PGP: %v", err)
	}
	fmt.Printf("Symmetric PGP ciphertext is not empty: %v\n", len(ciphertext) > 0)
	// Output:
	// Symmetric PGP ciphertext is not empty: true
}
