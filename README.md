# Enchantrix

Enchantrix is a modern encryption library for the Web3 era, designed to provide a secure and easy-to-use framework for handling sensitive data. It will feature Poly-ChaCha stream proxying and a custom `.trix` file format for encrypted data.

## Getting Started

To get started with Enchantrix, you'll need to have Go installed. You can then run the tests using the following command:

```shell
go test ./...
```

## Development Philosophy

This project follows a strict Test-Driven Development (TDD) methodology. All new functionality must be accompanied by a comprehensive suite of tests. We also leverage AI tools to accelerate development and ensure code quality.

## Usage

Here's a quick example of how to use the ChaCha20-Poly1305 encryption:

```go
package main

import (
	"fmt"
	"log"

	"github.com/Snider/Enchantrix/chachapoly"
)

func main() {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 1
	}

	plaintext := []byte("Hello, world!")
	ciphertext, err := chachapoly.Encrypt(plaintext, key)
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}

	decrypted, err := chachapoly.Decrypt(ciphertext, key)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}

	fmt.Printf("Decrypted message: %s\n", decrypted)
}
```

## Contributing

We welcome contributions! Please feel free to submit a pull request or open an issue.
