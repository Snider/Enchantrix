package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Snider/Enchantrix/pkg/crypt"
	"github.com/Snider/Enchantrix/pkg/crypt/std/chachapoly"
	"github.com/Snider/Enchantrix/pkg/enchantrix"
	"github.com/Snider/Enchantrix/pkg/trix"
)

func main() {
	demoTrix()
	demoHashing()
	demoChecksums()
	demoRSA()
	demoSigils()
}

func demoTrix() {
	fmt.Println("--- Trix & Sigil Chaining Demo ---")

	// 1. Original plaintext (JSON data) and encryption key
	type Message struct {
		Author string `json:"author"`
		Time   int64  `json:"time"`
		Body   string `json:"body"`
	}
	originalMessage := Message{Author: "Jules", Time: time.Now().Unix(), Body: "This is a super secret message!"}
	plaintext, err := json.Marshal(originalMessage)
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}
	key := make([]byte, 32) // In a real application, use a secure key
	for i := range key {
		key[i] = 1
	}

	fmt.Printf("Original Payload (JSON):\n%s\n\n", plaintext)

	// 2. Create a Trix container with the plaintext and attach a chain of sigils
	sigilChain := []string{"json-indent", "gzip", "base64", "reverse"}
	trixContainer := &trix.Trix{
		Header:   map[string]interface{}{},
		Payload:  plaintext,
		InSigils: sigilChain,
	}

	// 3. Pack the Trix container to apply the sigil transformations
	fmt.Println("Packing payload with sigils:", sigilChain)
	if err := trixContainer.Pack(); err != nil {
		log.Fatalf("Failed to pack trix container: %v", err)
	}
	fmt.Printf("Packed (obfuscated) payload is now non-human-readable bytes.\n\n")

	// 4. Encrypt the packed payload
	ciphertext, err := chachapoly.Encrypt(trixContainer.Payload, key)
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}
	trixContainer.Payload = ciphertext // Update the payload with the ciphertext

	// 5. Add encryption metadata and checksum to the header
	nonce := ciphertext[:24]
	trixContainer.Header = map[string]interface{}{
		"content_type":         "application/json",
		"encryption_algorithm": "chacha20poly1305",
		"nonce":                base64.StdEncoding.EncodeToString(nonce),
		"created_at":           time.Now().UTC().Format(time.RFC3339),
	}
	trixContainer.ChecksumAlgo = crypt.SHA512
	fmt.Printf("Checksum will be calculated with %s and added to the header.\n", trixContainer.ChecksumAlgo)

	// 6. Encode the .trix container into its binary format
	magicNumber := "MyT1"
	encodedTrix, err := trix.Encode(trixContainer, magicNumber, nil)
	if err != nil {
		log.Fatalf("Failed to encode .trix container: %v", err)
	}
	fmt.Println("Successfully created .trix container.")

	// --- DECODING ---
	fmt.Println("--- DECODING ---")

	// 7. Decode the .trix container
	decodedTrix, err := trix.Decode(encodedTrix, magicNumber, nil)
	if err != nil {
		log.Fatalf("Failed to decode .trix container: %v", err)
	}
	fmt.Println("Successfully decoded .trix container. Checksum verified.")
	fmt.Printf("Decoded Header: %+v\n", decodedTrix.Header)

	// 8. Decrypt the payload
	decryptedPayload, err := chachapoly.Decrypt(decodedTrix.Payload, key)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}
	decodedTrix.Payload = decryptedPayload
	fmt.Println("Payload decrypted.")

	// 9. Unpack the Trix container to reverse the sigil transformations
	decodedTrix.InSigils = trixContainer.InSigils // Re-attach sigils for unpacking
	fmt.Println("Unpacking payload by reversing sigils:", decodedTrix.InSigils)
	if err := decodedTrix.Unpack(); err != nil {
		log.Fatalf("Failed to unpack trix container: %v", err)
	}
	fmt.Printf("Unpacked (original) payload:\n%s\n", decodedTrix.Payload)

	// 10. Verify the result
	// To properly verify, we need to compact the indented JSON before comparing
	var compactedPayload bytes.Buffer
	if err := json.Compact(&compactedPayload, decodedTrix.Payload); err != nil {
		log.Fatalf("Failed to compact final payload for verification: %v", err)
	}

	if bytes.Equal(plaintext, compactedPayload.Bytes()) {
		fmt.Println("\nSuccess! The message was decrypted and unpacked correctly.")
	} else {
		fmt.Println("\nFailure! The final payload does not match the original.")
	}
	fmt.Println()
}

func demoHashing() {
	fmt.Println("--- Hashing Demo ---")
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
	fmt.Println()
}

func demoChecksums() {
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

func demoRSA() {
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

func demoSigils() {
	fmt.Println("--- Standalone Sigil Demo ---")
	data := []byte(`{"message": "hello world"}`)
	fmt.Printf("Original data: %s\n", data)

	// A chain of sigils to apply
	sigils := []string{"gzip", "base64"}
	fmt.Printf("Applying sigil chain: %v\n", sigils)

	var transformedData = data
	for _, name := range sigils {
		s, err := enchantrix.NewSigil(name)
		if err != nil {
			log.Fatalf("Failed to create sigil %s: %v", name, err)
		}
		transformedData, err = s.In(transformedData)
		if err != nil {
			log.Fatalf("Failed to apply sigil %s 'In': %v", name, err)
		}
		fmt.Printf(" -> After '%s': %s\n", name, transformedData)
	}

	fmt.Println("\nReversing sigil chain...")
	// Reverse the transformations
	for i := len(sigils) - 1; i >= 0; i-- {
		name := sigils[i]
		s, err := enchantrix.NewSigil(name)
		if err != nil {
			log.Fatalf("Failed to create sigil %s: %v", name, err)
		}
		transformedData, err = s.Out(transformedData)
		if err != nil {
			log.Fatalf("Failed to apply sigil %s 'Out': %v", name, err)
		}
		fmt.Printf(" -> After '%s' Out: %s\n", name, transformedData)
	}

	if string(data) == string(transformedData) {
		fmt.Println("Success! Data returned to original state.")
	} else {
		fmt.Println("Failure! Data did not return to original state.")
	}
	fmt.Println()
}
