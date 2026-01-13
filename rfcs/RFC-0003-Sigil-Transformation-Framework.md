# RFC-0003: Sigil Transformation Framework

**Status:** Standards Track
**Version:** 1.0
**Created:** 2025-01-13
**Author:** Snider

## Abstract

This document specifies the Sigil Transformation Framework, a composable interface for defining reversible and irreversible data transformations. Sigils provide a uniform abstraction for encoding, compression, hashing, encryption, and other byte-level operations, enabling declarative transformation pipelines that can be applied and reversed systematically.

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Interface Specification](#3-interface-specification)
4. [Sigil Categories](#4-sigil-categories)
5. [Standard Sigils](#5-standard-sigils)
6. [Composition and Chaining](#6-composition-and-chaining)
7. [Error Handling](#7-error-handling)
8. [Implementation Guidelines](#8-implementation-guidelines)
9. [Security Considerations](#9-security-considerations)
10. [References](#10-references)

## 1. Introduction

Data transformation is a fundamental operation in software systems. Common transformations include:

- **Encoding**: Converting between representations (hex, base64)
- **Compression**: Reducing data size (gzip, zstd)
- **Encryption**: Protecting confidentiality (AES, ChaCha20)
- **Hashing**: Computing digests (SHA-256, BLAKE2)
- **Formatting**: Restructuring data (JSON minification)

The Sigil framework provides a uniform interface for all these operations, enabling:

- Declarative transformation pipelines
- Automatic reversal of transformation chains
- Composable, reusable transformation units
- Clear semantics for reversible vs. irreversible operations

### 1.1 Design Principles

1. **Simplicity**: Two methods, clear contract
2. **Composability**: Sigils combine naturally
3. **Reversibility awareness**: Explicit handling of one-way operations
4. **Null safety**: Defined behavior for nil/empty inputs
5. **Error propagation**: Clear error semantics

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

**Sigil**: A transformation unit implementing the Sigil interface
**In operation**: The forward transformation (encode, compress, encrypt, hash)
**Out operation**: The reverse transformation (decode, decompress, decrypt)
**Reversible sigil**: A sigil where Out(In(x)) = x for all valid x
**Irreversible sigil**: A sigil where Out returns the input unchanged or errors
**Symmetric sigil**: A sigil where In(x) = Out(x) (e.g., byte reversal)
**Transmutation**: Applying a sequence of sigils to data

## 3. Interface Specification

### 3.1 Sigil Interface

```
interface Sigil {
    // In transforms the data (forward operation).
    // Returns transformed data and any error encountered.
    In(data: bytes) -> (bytes, error)

    // Out reverses the transformation (reverse operation).
    // For irreversible sigils, returns data unchanged.
    Out(data: bytes) -> (bytes, error)
}
```

### 3.2 Method Contracts

#### 3.2.1 In Method

The `In` method MUST:

- Accept a byte slice as input
- Return a byte slice as output
- Return nil output for nil input (without error)
- Return empty slice for empty input (without error)
- Return an error if transformation fails

#### 3.2.2 Out Method

The `Out` method MUST:

- Accept a byte slice as input
- Return a byte slice as output
- Return nil output for nil input (without error)
- Return empty slice for empty input (without error)
- For reversible sigils: return the original data before `In` was applied
- For irreversible sigils: return the input unchanged (passthrough)

### 3.3 Transmute Function

The framework provides a helper function for applying multiple sigils:

```
function Transmute(data: bytes, sigils: Sigil[]) -> (bytes, error):
    for each sigil in sigils:
        data, err = sigil.In(data)
        if err != nil:
            return nil, err
    return data, nil
```

## 4. Sigil Categories

### 4.1 Reversible Sigils

Reversible sigils can recover the original input from the output.

**Property**: For any valid input `x`:
```
sigil.Out(sigil.In(x)) == x
```

Examples:
- Encoding sigils (hex, base64)
- Compression sigils (gzip)
- Encryption sigils (ChaCha20-Poly1305)

### 4.2 Irreversible Sigils

Irreversible sigils perform one-way transformations.

**Property**: The `Out` method returns input unchanged:
```
sigil.Out(x) == x
```

Examples:
- Hash sigils (SHA-256, MD5)
- Truncation sigils

### 4.3 Symmetric Sigils

Symmetric sigils have identical `In` and `Out` operations.

**Property**: For any input `x`:
```
sigil.In(x) == sigil.Out(x)
```

Examples:
- Byte reversal
- XOR with fixed key
- Bitwise NOT

## 5. Standard Sigils

### 5.1 Encoding Sigils

#### 5.1.1 Hex Sigil

Encodes data to hexadecimal representation.

| Property | Value |
|----------|-------|
| Name | `hex` |
| Category | Reversible |
| In | Binary to hex ASCII |
| Out | Hex ASCII to binary |
| Output expansion | 2x |

```
In("Hello")  -> "48656c6c6f"
Out("48656c6c6f") -> "Hello"
```

#### 5.1.2 Base64 Sigil

Encodes data to Base64 representation (RFC 4648).

| Property | Value |
|----------|-------|
| Name | `base64` |
| Category | Reversible |
| In | Binary to Base64 ASCII |
| Out | Base64 ASCII to binary |
| Output expansion | ~1.33x |

```
In("Hello")  -> "SGVsbG8="
Out("SGVsbG8=") -> "Hello"
```

### 5.2 Transformation Sigils

#### 5.2.1 Reverse Sigil

Reverses the byte order of the data.

| Property | Value |
|----------|-------|
| Name | `reverse` |
| Category | Symmetric |
| In | Reverse bytes |
| Out | Reverse bytes |
| Output expansion | 1x |

```
In("Hello")  -> "olleH"
Out("olleH") -> "Hello"
```

### 5.3 Compression Sigils

#### 5.3.1 Gzip Sigil

Compresses data using gzip (RFC 1952).

| Property | Value |
|----------|-------|
| Name | `gzip` |
| Category | Reversible |
| In | Compress |
| Out | Decompress |
| Output expansion | Variable (typically < 1x) |

### 5.4 Formatting Sigils

#### 5.4.1 JSON Sigil

Compacts JSON data by removing whitespace.

| Property | Value |
|----------|-------|
| Name | `json` |
| Category | Reversible* |
| In | Compact JSON |
| Out | Passthrough |

*Note: Whitespace is not recoverable; Out returns input unchanged.

#### 5.4.2 JSON-Indent Sigil

Pretty-prints JSON data with indentation.

| Property | Value |
|----------|-------|
| Name | `json-indent` |
| Category | Reversible* |
| In | Indent JSON (2 spaces) |
| Out | Passthrough |

### 5.5 Hash Sigils

Hash sigils compute cryptographic digests. They are irreversible.

| Name | Algorithm | Output Size |
|------|-----------|-------------|
| `md4` | MD4 | 16 bytes |
| `md5` | MD5 | 16 bytes |
| `sha1` | SHA-1 | 20 bytes |
| `sha224` | SHA-224 | 28 bytes |
| `sha256` | SHA-256 | 32 bytes |
| `sha384` | SHA-384 | 48 bytes |
| `sha512` | SHA-512 | 64 bytes |
| `sha3-224` | SHA3-224 | 28 bytes |
| `sha3-256` | SHA3-256 | 32 bytes |
| `sha3-384` | SHA3-384 | 48 bytes |
| `sha3-512` | SHA3-512 | 64 bytes |
| `sha512-224` | SHA-512/224 | 28 bytes |
| `sha512-256` | SHA-512/256 | 32 bytes |
| `ripemd160` | RIPEMD-160 | 20 bytes |
| `blake2s-256` | BLAKE2s | 32 bytes |
| `blake2b-256` | BLAKE2b | 32 bytes |
| `blake2b-384` | BLAKE2b | 48 bytes |
| `blake2b-512` | BLAKE2b | 64 bytes |

For all hash sigils:
- `In(data)` returns the hash digest as raw bytes
- `Out(data)` returns data unchanged (passthrough)

## 6. Composition and Chaining

### 6.1 Forward Chain (Packing)

Sigils are applied left-to-right:

```
sigils = [gzip, base64, hex]
result = Transmute(data, sigils)

// Equivalent to:
result = hex.In(base64.In(gzip.In(data)))
```

### 6.2 Reverse Chain (Unpacking)

To reverse a chain, apply `Out` in reverse order:

```
function ReverseTransmute(data: bytes, sigils: Sigil[]) -> (bytes, error):
    for i = length(sigils) - 1 downto 0:
        data, err = sigils[i].Out(data)
        if err != nil:
            return nil, err
    return data, nil
```

### 6.3 Chain Properties

For a chain of reversible sigils `[s1, s2, s3]`:

```
original = ReverseTransmute(Transmute(data, [s1, s2, s3]), [s1, s2, s3])
// original == data
```

### 6.4 Mixed Chains

Chains MAY contain both reversible and irreversible sigils:

```
sigils = [gzip, sha256]  // sha256 is irreversible

packed = Transmute(data, sigils)
// packed is the SHA-256 hash of gzip-compressed data

unpacked = ReverseTransmute(packed, sigils)
// unpacked == packed (sha256.Out is passthrough)
```

## 7. Error Handling

### 7.1 Error Categories

| Category | Description | Recovery |
|----------|-------------|----------|
| Input error | Invalid input format | Check input validity |
| State error | Sigil not properly configured | Initialize sigil |
| Resource error | Memory/IO failure | Retry or abort |
| Algorithm error | Cryptographic failure | Check keys/params |

### 7.2 Error Propagation

Errors MUST propagate immediately:

```
function Transmute(data: bytes, sigils: Sigil[]) -> (bytes, error):
    for each sigil in sigils:
        data, err = sigil.In(data)
        if err != nil:
            return nil, err  // Stop immediately
    return data, nil
```

### 7.3 Partial Results

On error, implementations MUST NOT return partial results. Either:
- Return complete transformed data, or
- Return nil with an error

## 8. Implementation Guidelines

### 8.1 Sigil Factory

Implementations SHOULD provide a factory function:

```
function NewSigil(name: string) -> (Sigil, error):
    switch name:
        case "hex": return new HexSigil()
        case "base64": return new Base64Sigil()
        case "gzip": return new GzipSigil()
        // ... etc
        default: return nil, error("unknown sigil: " + name)
```

### 8.2 Null Safety

```
function In(data: bytes) -> (bytes, error):
    if data == nil:
        return nil, nil  // NOT an error
    if length(data) == 0:
        return [], nil   // Empty slice, NOT nil
    // ... perform transformation
```

### 8.3 Immutability

Sigils SHOULD NOT modify the input slice:

```
// CORRECT: Create new slice
result := make([]byte, len(data))
// ... transform into result

// INCORRECT: Modify in place
data[0] = transformed  // Don't do this
```

### 8.4 Thread Safety

Sigils SHOULD be safe for concurrent use:

- Avoid mutable state in sigil instances
- Use synchronization if state is required
- Document thread-safety guarantees

## 9. Security Considerations

### 9.1 Hash Sigil Security

- MD4, MD5, SHA1 are cryptographically broken for collision resistance
- Use SHA-256 or stronger for security-critical applications
- Hash sigils do NOT provide authentication

### 9.2 Compression Oracle Attacks

When combining compression and encryption sigils:
- Be aware of CRIME/BREACH-style attacks
- Do not compress data containing secrets alongside attacker-controlled data

### 9.3 Memory Safety

- Validate output buffer sizes before allocation
- Implement maximum input size limits
- Handle decompression bombs (zip bombs)

### 9.4 Timing Attacks

- Comparison operations should be constant-time where security-relevant
- Hash comparisons should use constant-time comparison functions

## 10. References

- [RFC 4648] The Base16, Base32, and Base64 Data Encodings
- [RFC 1952] GZIP file format specification
- [RFC 8259] The JavaScript Object Notation (JSON) Data Interchange Format
- [FIPS 180-4] Secure Hash Standard
- [FIPS 202] SHA-3 Standard

---

## Appendix A: Sigil Name Registry

| Name | Category | Reversible | Notes |
|------|----------|------------|-------|
| `reverse` | Transform | Yes (symmetric) | Byte reversal |
| `hex` | Encoding | Yes | Hexadecimal |
| `base64` | Encoding | Yes | RFC 4648 |
| `gzip` | Compression | Yes | RFC 1952 |
| `json` | Formatting | Partial | Compacts JSON |
| `json-indent` | Formatting | Partial | Pretty-prints JSON |
| `md4` | Hash | No | 128-bit |
| `md5` | Hash | No | 128-bit |
| `sha1` | Hash | No | 160-bit |
| `sha224` | Hash | No | 224-bit |
| `sha256` | Hash | No | 256-bit |
| `sha384` | Hash | No | 384-bit |
| `sha512` | Hash | No | 512-bit |
| `sha3-*` | Hash | No | SHA-3 family |
| `sha512-*` | Hash | No | SHA-512 truncated |
| `ripemd160` | Hash | No | 160-bit |
| `blake2s-256` | Hash | No | 256-bit |
| `blake2b-*` | Hash | No | BLAKE2b family |

## Appendix B: Reference Implementation

A reference implementation in Go is available at:
- Interface: `github.com/Snider/Enchantrix/pkg/enchantrix/enchantrix.go`
- Standard sigils: `github.com/Snider/Enchantrix/pkg/enchantrix/sigils.go`

## Appendix C: Custom Sigil Example

```go
// ROT13Sigil implements a simple letter rotation cipher.
type ROT13Sigil struct{}

func (s *ROT13Sigil) In(data []byte) ([]byte, error) {
    if data == nil {
        return nil, nil
    }
    result := make([]byte, len(data))
    for i, b := range data {
        if b >= 'A' && b <= 'Z' {
            result[i] = 'A' + (b-'A'+13)%26
        } else if b >= 'a' && b <= 'z' {
            result[i] = 'a' + (b-'a'+13)%26
        } else {
            result[i] = b
        }
    }
    return result, nil
}

func (s *ROT13Sigil) Out(data []byte) ([]byte, error) {
    return s.In(data)  // ROT13 is symmetric
}
```

## Appendix D: Changelog

- **1.0** (2025-01-13): Initial specification
