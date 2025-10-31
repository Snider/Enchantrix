package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/Snider/Enchantrix/pkg/crypt/std/chachapoly"
	"github.com/Snider/Enchantrix/pkg/trix"
)

func main() {
	// 1. Original plaintext and encryption key
	plaintext := []byte("This is a super secret message!")
	key := make([]byte, 32) // In a real application, use a secure key
	for i := range key {
		key[i] = 1
	}

	// 2. Create a Trix container with the plaintext and attach sigils
	trixContainer := &trix.Trix{
		Header:  map[string]interface{}{},
		Payload: plaintext,
		Sigils:  []trix.Sigil{&trix.ReverseSigil{}},
	}

	// 3. Pack the Trix container to apply the sigil transformations
	if err := trixContainer.Pack(); err != nil {
		log.Fatalf("Failed to pack trix container: %v", err)
	}
	fmt.Printf("Packed (obfuscated) payload: %x\n", trixContainer.Payload)


	// 4. Encrypt the packed payload
	ciphertext, err := chachapoly.Encrypt(trixContainer.Payload, key)
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}
	trixContainer.Payload = ciphertext // Update the payload with the ciphertext

	// 5. Add encryption metadata to the header
	nonce := ciphertext[:24]
	trixContainer.Header = map[string]interface{}{
		"content_type":         "application/octet-stream",
		"encryption_algorithm": "chacha20poly1305",
		"nonce":                base64.StdEncoding.EncodeToString(nonce),
		"created_at":           time.Now().UTC().Format(time.RFC3339),
	}


	// 6. Encode the .trix container into its binary format
	magicNumber := "MyT1"
	encodedTrix, err := trix.Encode(trixContainer, magicNumber)
	if err != nil {
		log.Fatalf("Failed to encode .trix container: %v", err)
	}
	fmt.Println("Successfully created .trix container.")

	// --- DECODING ---

	// 7. Decode the .trix container
	decodedTrix, err := trix.Decode(encodedTrix, magicNumber)
	if err != nil {
		log.Fatalf("Failed to decode .trix container: %v", err)
	}

	// 8. Decrypt the payload
	decryptedPayload, err := chachapoly.Decrypt(decodedTrix.Payload, key)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}
	decodedTrix.Payload = decryptedPayload

	// 9. Unpack the Trix container to reverse the sigil transformations
	decodedTrix.Sigils = trixContainer.Sigils // Re-attach sigils
	if err := decodedTrix.Unpack(); err != nil {
		log.Fatalf("Failed to unpack trix container: %v", err)
	}
	fmt.Printf("Unpacked (original) payload: %s\n", decodedTrix.Payload)

	// 10. Verify the result
	if string(plaintext) == string(decodedTrix.Payload) {
		fmt.Println("\nSuccess! The message was decrypted and unpacked correctly.")
	} else {
		fmt.Println("\nFailure! The final payload does not match the original.")
	}
}
