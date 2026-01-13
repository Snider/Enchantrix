# Enchantrix

[![Go Report Card](https://goreportcard.com/badge/github.com/Snider/Enchantrix)](https://goreportcard.com/report/github.com/Snider/Enchantrix)
[![GoDoc](https://godoc.org/github.com/Snider/Enchantrix?status.svg)](https://godoc.org/github.com/Snider/Enchantrix)
[![Build Status](https://github.com/Snider/Enchantrix/actions/workflows/go.yml/badge.svg)](https://github.com/Snider/Enchantrix/actions/workflows/go.yml)
[![codecov](https://codecov.io/github/Snider/Enchantrix/branch/main/graph/badge.svg?token=2E1QWEDFUW)](https://codecov.io/github/Snider/Enchantrix)
[![Release](https://img.shields.io/github/release/Snider/Enchantrix.svg)](https://github.com/Snider/Enchantrix/releases/latest)
[![License](https://img.shields.io/github/license/Snider/Enchantrix)](https://github.com/Snider/Enchantrix/blob/main/LICENCE)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://go.dev/)

A Go-based encryption and data transformation library designed for secure handling of sensitive data. Enchantrix provides composable transformation pipelines, a flexible binary container format, and defense-in-depth encryption with pre-obfuscation.

## Features

- **Sigil Transformation Framework** - Composable, reversible data transformations (encoding, compression, hashing)
- **Pre-Obfuscation Layer** - Side-channel attack mitigation for AEAD ciphers
- **.trix Container Format** - Protocol-agnostic binary format with JSON metadata
- **Multiple Hash Algorithms** - SHA-2, SHA-3, BLAKE2, RIPEMD-160, and the custom LTHN algorithm
- **Full PGP Support** - Key generation, encryption, decryption, signing, and verification
- **RSA Operations** - Key generation, encryption, and decryption
- **CLI Tool** - `trix` command for encoding, decoding, and transformations

## Quick Start

### Installation

```shell
go get github.com/Snider/Enchantrix
```

### Install CLI Tool

```shell
go install github.com/Snider/Enchantrix/cmd/trix@latest
```

### Basic Usage

#### Sigil Transformations

```go
package main

import (
    "fmt"
    "github.com/Snider/Enchantrix/pkg/enchantrix"
)

func main() {
    // Create sigils
    hexSigil, _ := enchantrix.NewSigil("hex")
    base64Sigil, _ := enchantrix.NewSigil("base64")

    // Apply transformations
    data := []byte("Hello, Enchantrix!")
    encoded, _ := enchantrix.Transmute(data, []enchantrix.Sigil{hexSigil, base64Sigil})

    fmt.Printf("Encoded: %s\n", encoded)
}
```

#### Hashing

```go
package main

import (
    "fmt"
    "github.com/Snider/Enchantrix/pkg/crypt"
)

func main() {
    service := crypt.NewService()

    hash := service.Hash(crypt.SHA256, "Hello, World!")
    fmt.Printf("SHA-256: %s\n", hash)

    // LTHN quasi-salted hash
    lthnHash := service.Hash(crypt.LTHN, "Hello, World!")
    fmt.Printf("LTHN: %s\n", lthnHash)
}
```

#### Encrypted .trix Container

```go
package main

import (
    "fmt"
    "github.com/Snider/Enchantrix/pkg/trix"
)

func main() {
    container := &trix.Trix{
        Header: map[string]interface{}{
            "content_type": "text/plain",
            "created_at":   "2025-01-13T12:00:00Z",
        },
        Payload:  []byte("Secret message"),
        InSigils: []string{"gzip", "base64"},
    }

    // Pack with sigils
    container.Pack()

    // Encode to binary
    encoded, _ := trix.Encode(container, "MYAP", nil)
    fmt.Printf("Container size: %d bytes\n", len(encoded))
}
```

### CLI Examples

```shell
# Encode with sigils
echo "Hello, Trix!" | trix encode --output message.trix --magic TRIX base64

# Decode
trix decode --input message.trix --output message.txt --magic TRIX base64

# Hash data
echo "Hello, World!" | trix hash sha256

# Apply sigil directly
echo "Hello" | trix hex
# Output: 48656c6c6f
```

## Specifications

Enchantrix includes formal RFC-style specifications for its core protocols:

| RFC | Title | Description |
|-----|-------|-------------|
| [RFC-0001](rfcs/RFC-0001-Pre-Obfuscation-Layer.md) | Pre-Obfuscation Layer | Side-channel mitigation for AEAD ciphers |
| [RFC-0002](rfcs/RFC-0002-Trix-Container-Format.md) | TRIX Container Format | Binary container with JSON metadata |
| [RFC-0003](rfcs/RFC-0003-Sigil-Transformation-Framework.md) | Sigil Framework | Composable data transformation interface |
| [RFC-0004](rfcs/RFC-0004-LTHN-Hash-Algorithm.md) | LTHN Hash | Quasi-salted deterministic hashing |

## Available Sigils

| Category | Sigils |
|----------|--------|
| **Encoding** | `hex`, `base64` |
| **Compression** | `gzip` |
| **Formatting** | `json`, `json-indent` |
| **Transform** | `reverse` |
| **Hashing** | `md4`, `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`, `sha512-224`, `sha512-256`, `ripemd160`, `blake2s-256`, `blake2b-256`, `blake2b-384`, `blake2b-512` |

## Project Structure

```
Enchantrix/
├── cmd/trix/           # CLI tool
├── pkg/
│   ├── enchantrix/     # Sigil framework and crypto sigils
│   ├── trix/           # .trix container format
│   └── crypt/          # Cryptographic services (hash, RSA, PGP)
├── rfcs/               # Protocol specifications
├── examples/           # Usage examples
└── docs/               # MkDocs documentation
```

## Documentation

Full documentation is available via MkDocs:

```shell
# Install dependencies
pip install mkdocs mkdocs-material

# Serve locally
mkdocs serve -a 127.0.0.1:8000

# Build static site
mkdocs build --strict
```

## Development

### Requirements

- Go 1.25 or later

### Running Tests

```shell
# Run all tests
go test ./...

# Run with race detection
go test -race ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
```

### Test-Driven Development

This project follows strict TDD methodology. All new functionality must include comprehensive tests.

## Releases

Built with GoReleaser:

```shell
# Snapshot release (local, no publish)
goreleaser release --snapshot --clean

# Production release (requires Git tag)
goreleaser release --clean
```

## License

See [LICENCE](LICENCE) for details.
