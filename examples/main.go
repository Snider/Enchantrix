package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/Snider/Enchantrix/chachapoly"
	"github.com/Snider/Enchantrix/trix"
)

func main() {
	// 1. Original plaintext
	plaintext := []byte("This is a super secret message!")
	key := make([]byte, 32) // In a real application, use a secure key
	for i := range key {
		key[i] = 1
	}

	// 2. Encrypt the data using the chachapoly package
	// The ciphertext from chachapoly includes the nonce.
	ciphertext, err := chachapoly.Encrypt(plaintext, key)
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}

	// For the .trix header, we need to separate the nonce from the ciphertext.
	// chacha20poly1305.NewX nonce size is 24 bytes.
	nonce := ciphertext[:24]
	actualCiphertext := ciphertext[24:]

	// 3. Create a .trix container for the encrypted data
	header := map[string]interface{}{
		"content_type":         "application/octet-stream",
		"encryption_algorithm": "chacha20poly1305",
		"nonce":                base64.StdEncoding.EncodeToString(nonce),
		"created_at":           time.Now().UTC().Format(time.RFC3339),
	}

	trixContainer := &trix.Trix{
		Header:  header,
		Payload: actualCiphertext,
	}

	// 4. Encode the .trix container into its binary format
	encodedTrix, err := trix.Encode(trixContainer)
	if err != nil {
		log.Fatalf("Failed to encode .trix container: %v", err)
	}

	fmt.Println("Successfully created .trix container.")

	// 5. Decode the .trix container to retrieve the encrypted data
	decodedTrix, err := trix.Decode(encodedTrix)
	if err != nil {
		log.Fatalf("Failed to decode .trix container: %v", err)
	}

	// 6. Reassemble the ciphertext (nonce + payload) and decrypt
	retrievedNonceStr, ok := decodedTrix.Header["nonce"].(string)
	if !ok {
		log.Fatalf("Nonce not found or not a string in header")
	}
	retrievedNonce, err := base64.StdEncoding.DecodeString(retrievedNonceStr)
	if err != nil {
		log.Fatalf("Failed to decode nonce: %v", err)
	}
	retrievedCiphertext := append(retrievedNonce, decodedTrix.Payload...)

	decrypted, err := chachapoly.Decrypt(retrievedCiphertext, key)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}

	// 7. Verify the result
	fmt.Printf("Original plaintext:  %s\n", plaintext)
	fmt.Printf("Decrypted plaintext: %s\n", decrypted)

	if string(plaintext) == string(decrypted) {
		fmt.Println("\nSuccess! The message was decrypted correctly.")
	} else {
		fmt.Println("\nFailure! The decrypted message does not match the original.")
	}
}
