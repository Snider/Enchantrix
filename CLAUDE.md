# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```shell
# Run all tests with coverage
go test -v -coverprofile=coverage.out ./...

# Run a single test
go test -v -run TestName ./pkg/enchantrix

# Run tests with race detection (as CI does)
go test -race -coverprofile=coverage.out -covermode=atomic ./...

# Run fuzz tests (CI runs 10s)
go test -run=Fuzz -fuzz=Fuzz -fuzztime=10s ./pkg/trix

# Build
go build -v ./...

# Vet
go vet ./...

# Format
go fmt ./...
```

If Task is installed, these are available:
- `task test` - Run tests with coverage
- `task build` - Build project
- `task fmt` - Format code
- `task vet` - Run go vet

## Architecture

Enchantrix is an encryption library with a custom `.trix` file format and CLI tool.

### Core Packages

**pkg/enchantrix** - Core transformation framework
- `Sigil` interface: defines `In(data)` and `Out(data)` for reversible/irreversible transforms
- `Transmute()`: applies a chain of sigils to data
- Built-in sigils: `reverse`, `hex`, `base64`, `gzip`, `json`, `json-indent`
- Hash sigils: `md4`, `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `ripemd160`, `sha3-*`, `sha512-*`, `blake2s-256`, `blake2b-*`
- `NewSigil(name)`: factory function to create sigils by string name
- `ChaChaPolySigil`: encryption sigil using XChaCha20-Poly1305 with pre-obfuscation layer

**pkg/trix** - Binary file format (.trix)
- Format: `[4-byte magic][1-byte version][4-byte header len][JSON header][payload]`
- `Encode()`: serializes Trix struct to binary
- `Decode()`: deserializes binary to Trix struct
- `Pack()`/`Unpack()`: apply/reverse sigils on payload
- Supports optional checksums via `ChecksumAlgo` field

**pkg/crypt** - Cryptographic services facade
- `Service`: aggregates hashing, checksums, RSA, and PGP operations
- Hash types: `lthn` (custom), `sha512`, `sha256`, `sha1`, `md5`
- Checksums: `Luhn()`, `Fletcher16/32/64()`
- RSA: key generation, encrypt/decrypt via `pkg/crypt/std/rsa`
- PGP: key generation, encrypt/decrypt, sign/verify, symmetric encrypt via `pkg/crypt/std/pgp`

**cmd/trix** - CLI tool (Cobra-based)
- `trix encode --magic XXXX --output file [sigils...]`
- `trix decode --magic XXXX --output file [sigils...]`
- `trix hash [algorithm]`
- `trix [sigil]` - apply any sigil directly

### Key Design Patterns

1. **Sigil Chain**: Transformations are composable. Encoding chains sigils in order; decoding reverses.
2. **Pre-Obfuscation**: `ChaChaPolySigil` applies XOR or shuffle-mask obfuscation before encryption so raw plaintext never goes directly to CPU encryption routines.
3. **Streaming Support**: `Encode()`/`Decode()` accept optional `io.Writer`/`io.Reader` for streaming.

## Testing Conventions

- Tests use `testify/assert` and `testify/require`
- Test files follow `*_test.go` pattern adjacent to implementation
- `examples_test.go` files contain example functions for godoc
- Fuzz tests exist in `pkg/trix` (`go test -fuzz`)

## Go Version

Minimum Go 1.25. Uses `go.work` for workspace management.
