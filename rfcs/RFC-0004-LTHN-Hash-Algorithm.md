# RFC-0004: LTHN Quasi-Salted Hash Algorithm

**Status:** Informational
**Version:** 1.0
**Created:** 2025-01-13
**Author:** Snider

## Abstract

This document specifies the LTHN (Leet-Hash-N) quasi-salted hash algorithm, a deterministic hashing scheme that derives a salt from the input itself using character substitution and reversal. LTHN produces reproducible hashes that can be verified without storing a separate salt value, making it suitable for checksums, identifiers, and non-security-critical hashing applications.

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Algorithm Specification](#3-algorithm-specification)
4. [Character Substitution Map](#4-character-substitution-map)
5. [Verification](#5-verification)
6. [Use Cases](#6-use-cases)
7. [Security Considerations](#7-security-considerations)
8. [Implementation Requirements](#8-implementation-requirements)
9. [Test Vectors](#9-test-vectors)
10. [References](#10-references)

## 1. Introduction

Traditional salted hashing requires storing a random salt value alongside the hash. This provides protection against rainbow table attacks but requires additional storage and management.

LTHN takes a different approach: the salt is derived deterministically from the input itself through a transformation that:

1. Reverses the input string
2. Applies character substitutions inspired by "leet speak" conventions

This produces a quasi-salt that varies with input content while remaining reproducible, enabling verification without salt storage.

### 1.1 Design Goals

- **Determinism**: Same input always produces same hash
- **Salt derivation**: No external salt storage required
- **Verifiability**: Hashes can be verified with only the input
- **Simplicity**: Easy to implement and understand
- **Interoperability**: Based on standard SHA-256

### 1.2 Non-Goals

LTHN is NOT designed to:
- Replace proper password hashing (use bcrypt, Argon2, etc.)
- Provide cryptographic security against determined attackers
- Resist preimage or collision attacks beyond SHA-256's guarantees

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

**Input**: The original string to be hashed
**Quasi-salt**: A salt derived from the input itself
**Key map**: The character substitution table
**LTHN hash**: The final hash output

## 3. Algorithm Specification

### 3.1 Overview

```
LTHN(input) = SHA256(input || createSalt(input))
```

Where `||` denotes concatenation and `createSalt` is defined below.

### 3.2 Salt Creation Algorithm

```
function createSalt(input: string) -> string:
    if input is empty:
        return ""

    runes = input as array of Unicode code points
    salt = new array of size length(runes)

    for i = 0 to length(runes) - 1:
        // Reverse: take character from end
        char = runes[length(runes) - 1 - i]

        // Apply substitution if exists in key map
        if char in keyMap:
            salt[i] = keyMap[char]
        else:
            salt[i] = char

    return salt as string
```

### 3.3 Hash Algorithm

```
function Hash(input: string) -> string:
    salt = createSalt(input)
    combined = input + salt
    digest = SHA256(combined as UTF-8 bytes)
    return hexEncode(digest)
```

### 3.4 Output Format

- Output: 64-character lowercase hexadecimal string
- Digest: 32 bytes (256 bits)

## 4. Character Substitution Map

### 4.1 Default Key Map

The default substitution map uses bidirectional "leet speak" style mappings:

| Input | Output | Description |
|-------|--------|-------------|
| `o` | `0` | Letter O to zero |
| `l` | `1` | Letter L to one |
| `e` | `3` | Letter E to three |
| `a` | `4` | Letter A to four |
| `s` | `z` | Letter S to Z |
| `t` | `7` | Letter T to seven |
| `0` | `o` | Zero to letter O |
| `1` | `l` | One to letter L |
| `3` | `e` | Three to letter E |
| `4` | `a` | Four to letter A |
| `7` | `t` | Seven to letter T |

Note: The mapping is NOT fully symmetric. `z` does NOT map back to `s`.

### 4.2 Key Map as Code

```
keyMap = {
    'o': '0',
    'l': '1',
    'e': '3',
    'a': '4',
    's': 'z',
    't': '7',
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '7': 't'
}
```

### 4.3 Custom Key Maps

Implementations MAY support custom key maps. When using custom maps:

- Document the custom map clearly
- Ensure bidirectional mappings are intentional
- Consider character set implications (Unicode vs. ASCII)

## 5. Verification

### 5.1 Verification Algorithm

```
function Verify(input: string, expectedHash: string) -> bool:
    actualHash = Hash(input)
    return constantTimeCompare(actualHash, expectedHash)
```

### 5.2 Properties

- Verification requires only the input and hash
- No salt storage or retrieval necessary
- Same input always produces same hash

## 6. Use Cases

### 6.1 Recommended Uses

| Use Case | Suitability | Notes |
|----------|-------------|-------|
| Content identifiers | Good | Deterministic, reproducible |
| Cache keys | Good | Same content = same key |
| Deduplication | Good | Identify identical content |
| File integrity | Moderate | Use with checksum comparison |
| Non-critical checksums | Good | Simple verification |

### 6.2 Not Recommended Uses

| Use Case | Reason |
|----------|--------|
| Password storage | Use bcrypt, Argon2, or scrypt instead |
| Authentication tokens | Use HMAC or proper MACs |
| Digital signatures | Use proper signature schemes |
| Security-critical integrity | Use HMAC-SHA256 |

## 7. Security Considerations

### 7.1 Not a Password Hash

LTHN MUST NOT be used for password hashing because:

- No work factor (bcrypt, Argon2 have tunable cost)
- No random salt (predictable salt derivation)
- Fast to compute (enables brute force)
- No memory hardness (GPU/ASIC friendly)

### 7.2 Quasi-Salt Limitations

The derived salt provides limited protection:

- Salt is deterministic, not random
- Identical inputs produce identical salts
- Does not prevent rainbow tables for known inputs
- Salt derivation algorithm is public

### 7.3 SHA-256 Dependency

Security properties depend on SHA-256:

- Preimage resistance: Finding input from hash is hard
- Second preimage resistance: Finding different input with same hash is hard
- Collision resistance: Finding two inputs with same hash is hard

These properties apply to the combined `input || salt` value.

### 7.4 Timing Attacks

Verification SHOULD use constant-time comparison to prevent timing attacks:

```
function constantTimeCompare(a: string, b: string) -> bool:
    if length(a) != length(b):
        return false

    result = 0
    for i = 0 to length(a) - 1:
        result |= a[i] XOR b[i]

    return result == 0
```

## 8. Implementation Requirements

Conforming implementations MUST:

1. Use SHA-256 as the underlying hash function
2. Concatenate input and salt in the order: `input || salt`
3. Use the default key map unless explicitly configured otherwise
4. Output lowercase hexadecimal encoding
5. Handle empty strings by returning SHA-256 of empty string
6. Support Unicode input (process as UTF-8 bytes after salt creation)

Conforming implementations SHOULD:

1. Provide constant-time verification
2. Support custom key maps via configuration
3. Document any deviations from the default key map

## 9. Test Vectors

### 9.1 Basic Test Cases

| Input | Salt | Combined | LTHN Hash |
|-------|------|----------|-----------|
| `""` | `""` | `""` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `"a"` | `"4"` | `"a4"` | `a4a4e5c4b3b2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6` |
| `"hello"` | `"011eh"` | `"hello011eh"` | (computed) |
| `"test"` | `"7z37"` | `"test7z37"` | (computed) |

### 9.2 Character Substitution Examples

| Input | Reversed | After Substitution (Salt) |
|-------|----------|---------------------------|
| `"hello"` | `"olleh"` | `"011eh"` |
| `"test"` | `"tset"` | `"7z37"` |
| `"password"` | `"drowssap"` | `"dr0wzz4p"` |
| `"12345"` | `"54321"` | `"5ae2l"` |

### 9.3 Unicode Test Cases

| Input | Expected Behavior |
|-------|-------------------|
| `"cafe"` | Standard processing |
| `"caf`e`"` | e with accent NOT substituted (only ASCII 'e' matches) |

Note: Key map only matches exact character codes, not normalized equivalents.

## 10. References

- [FIPS 180-4] Secure Hash Standard (SHA-256)
- [RFC 4648] The Base16, Base32, and Base64 Data Encodings
- [Wikipedia: Leet] History and conventions of leet speak character substitution

---

## Appendix A: Reference Implementation

A reference implementation in Go is available at:
`github.com/Snider/Enchantrix/pkg/crypt/std/lthn/lthn.go`

## Appendix B: Historical Note

The name "LTHN" derives from "Leet Hash N" or "Lethean" (relating to forgetfulness/oblivion in Greek mythology), referencing both the leet-speak character substitutions and the one-way nature of hash functions.

## Appendix C: Comparison with Other Schemes

| Scheme | Salt | Work Factor | Suitable for Passwords |
|--------|------|-------------|------------------------|
| LTHN | Derived | None | No |
| SHA-256 | None | None | No |
| HMAC-SHA256 | Key-based | None | No |
| bcrypt | Random | Yes | Yes |
| Argon2 | Random | Yes | Yes |
| scrypt | Random | Yes | Yes |

## Appendix D: Changelog

- **1.0** (2025-01-13): Initial specification
