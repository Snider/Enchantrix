# RFC-0001: Pre-Obfuscation Layer Protocol for AEAD Ciphers

**Status:** Informational
**Version:** 1.0
**Created:** 2025-01-13
**Author:** Snider

## Abstract

This document specifies a pre-obfuscation layer protocol designed to transform plaintext data before it reaches CPU encryption routines. The protocol provides an additional security layer that prevents raw plaintext patterns from being processed directly by encryption hardware, mitigating potential side-channel attack vectors while maintaining full compatibility with standard AEAD cipher constructions.

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Protocol Overview](#3-protocol-overview)
4. [Obfuscator Implementations](#4-obfuscator-implementations)
5. [Integration with AEAD Ciphers](#5-integration-with-aead-ciphers)
6. [Wire Format](#6-wire-format)
7. [Security Considerations](#7-security-considerations)
8. [Implementation Requirements](#8-implementation-requirements)
9. [Test Vectors](#9-test-vectors)
10. [References](#10-references)

## 1. Introduction

Modern AEAD (Authenticated Encryption with Associated Data) ciphers like ChaCha20-Poly1305 and AES-GCM provide strong cryptographic guarantees. However, the plaintext data is processed directly by CPU encryption instructions, potentially exposing patterns through side-channel attacks such as timing analysis, power analysis, or electromagnetic emanation.

This RFC defines a pre-obfuscation layer that transforms plaintext into an unpredictable byte sequence before encryption. The transformation is reversible, deterministic (given the same entropy source), and adds negligible overhead while providing defense-in-depth against side-channel attacks.

### 1.1 Design Goals

- **Reversibility**: All transformations MUST be perfectly reversible
- **Determinism**: Given the same entropy, transformations MUST produce identical results
- **Independence**: The obfuscation layer operates independently of the underlying cipher
- **Zero overhead on security**: The underlying AEAD cipher's security properties are preserved
- **Minimal computational overhead**: Transformations should add < 5% processing time

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

**Plaintext**: The original data to be encrypted
**Obfuscated data**: Plaintext after pre-obfuscation transformation
**Ciphertext**: Obfuscated data after encryption
**Entropy**: A source of randomness used to derive transformation parameters (typically the nonce)
**Key stream**: A deterministic sequence of bytes derived from entropy
**Permutation**: A bijective mapping of byte positions

## 3. Protocol Overview

The pre-obfuscation protocol operates in two stages:

### 3.1 Encryption Flow

```
Plaintext --> Obfuscate(plaintext, entropy) --> Obfuscated --> Encrypt --> Ciphertext
```

1. Generate cryptographic nonce for the AEAD cipher
2. Apply obfuscation transformation using nonce as entropy
3. Encrypt the obfuscated data using the AEAD cipher
4. Output: `[nonce || ciphertext || auth_tag]`

### 3.2 Decryption Flow

```
Ciphertext --> Decrypt --> Obfuscated --> Deobfuscate(obfuscated, entropy) --> Plaintext
```

1. Extract nonce from the ciphertext prefix
2. Decrypt the ciphertext using the AEAD cipher
3. Apply reverse obfuscation transformation using the extracted nonce
4. Output: Original plaintext

### 3.3 Entropy Derivation

The entropy source MUST be the same value used as the AEAD cipher nonce. This ensures:

- No additional random values need to be generated or stored
- The obfuscation is tied to the specific encryption operation
- Replay of ciphertext with different obfuscation is not possible

## 4. Obfuscator Implementations

This RFC defines two standard obfuscator implementations. Implementations MAY support additional obfuscators provided they meet the requirements in Section 8.

### 4.1 XOR Obfuscator

The XOR obfuscator generates a deterministic key stream from the entropy and XORs it with the plaintext.

#### 4.1.1 Key Stream Derivation

```
function deriveKeyStream(entropy: bytes, length: int) -> bytes:
    stream = empty byte array of size length
    blockNum = 0
    offset = 0

    while offset < length:
        block = SHA256(entropy || BigEndian64(blockNum))
        copyLen = min(32, length - offset)
        copy block[0:copyLen] to stream[offset:offset+copyLen]
        offset += copyLen
        blockNum += 1

    return stream
```

#### 4.1.2 Obfuscation

```
function obfuscate(data: bytes, entropy: bytes) -> bytes:
    if length(data) == 0:
        return data

    keyStream = deriveKeyStream(entropy, length(data))
    result = new byte array of size length(data)

    for i = 0 to length(data) - 1:
        result[i] = data[i] XOR keyStream[i]

    return result
```

#### 4.1.3 Deobfuscation

The XOR operation is symmetric; deobfuscation uses the same algorithm:

```
function deobfuscate(data: bytes, entropy: bytes) -> bytes:
    return obfuscate(data, entropy)  // XOR is self-inverse
```

### 4.2 Shuffle-Mask Obfuscator

The shuffle-mask obfuscator provides additional diffusion by combining a byte-level shuffle with an XOR mask.

#### 4.2.1 Permutation Generation

Uses Fisher-Yates shuffle with deterministic randomness:

```
function generatePermutation(entropy: bytes, length: int) -> int[]:
    perm = [0, 1, 2, ..., length-1]
    seed = SHA256(entropy || "permutation")

    for i = length-1 downto 1:
        hash = SHA256(seed || BigEndian64(i))
        j = BigEndian64(hash[0:8]) mod (i + 1)
        swap perm[i] and perm[j]

    return perm
```

#### 4.2.2 Mask Derivation

```
function deriveMask(entropy: bytes, length: int) -> bytes:
    mask = empty byte array of size length
    blockNum = 0
    offset = 0

    while offset < length:
        block = SHA256(entropy || "mask" || BigEndian64(blockNum))
        copyLen = min(32, length - offset)
        copy block[0:copyLen] to mask[offset:offset+copyLen]
        offset += copyLen
        blockNum += 1

    return mask
```

#### 4.2.3 Obfuscation

```
function obfuscate(data: bytes, entropy: bytes) -> bytes:
    if length(data) == 0:
        return data

    perm = generatePermutation(entropy, length(data))
    mask = deriveMask(entropy, length(data))

    // Step 1: Apply mask
    masked = new byte array of size length(data)
    for i = 0 to length(data) - 1:
        masked[i] = data[i] XOR mask[i]

    // Step 2: Shuffle bytes according to permutation
    shuffled = new byte array of size length(data)
    for i = 0 to length(data) - 1:
        shuffled[i] = masked[perm[i]]

    return shuffled
```

#### 4.2.4 Deobfuscation

```
function deobfuscate(data: bytes, entropy: bytes) -> bytes:
    if length(data) == 0:
        return data

    perm = generatePermutation(entropy, length(data))
    mask = deriveMask(entropy, length(data))

    // Step 1: Unshuffle bytes (inverse permutation)
    unshuffled = new byte array of size length(data)
    for i = 0 to length(data) - 1:
        unshuffled[perm[i]] = data[i]

    // Step 2: Remove mask
    result = new byte array of size length(data)
    for i = 0 to length(data) - 1:
        result[i] = unshuffled[i] XOR mask[i]

    return result
```

## 5. Integration with AEAD Ciphers

### 5.1 XChaCha20-Poly1305 Integration

When used with XChaCha20-Poly1305:

- Nonce size: 24 bytes
- Key size: 32 bytes
- Auth tag size: 16 bytes

```
function encrypt(key: bytes[32], plaintext: bytes) -> bytes:
    nonce = random_bytes(24)
    obfuscated = obfuscator.obfuscate(plaintext, nonce)
    ciphertext = XChaCha20Poly1305_Seal(key, nonce, obfuscated, nil)
    return nonce || ciphertext  // nonce is prepended
```

```
function decrypt(key: bytes[32], data: bytes) -> bytes:
    if length(data) < 24 + 16:  // nonce + auth tag minimum
        return error("ciphertext too short")

    nonce = data[0:24]
    ciphertext = data[24:]
    obfuscated = XChaCha20Poly1305_Open(key, nonce, ciphertext, nil)
    plaintext = obfuscator.deobfuscate(obfuscated, nonce)
    return plaintext
```

### 5.2 Other AEAD Ciphers

The pre-obfuscation layer is cipher-agnostic. For other AEAD ciphers:

| Cipher | Nonce Size | Notes |
|--------|------------|-------|
| AES-128-GCM | 12 bytes | Standard nonce |
| AES-256-GCM | 12 bytes | Standard nonce |
| ChaCha20-Poly1305 | 12 bytes | Original ChaCha nonce |
| XChaCha20-Poly1305 | 24 bytes | Extended nonce (RECOMMENDED) |

## 6. Wire Format

The output wire format is:

```
+----------------+------------------------+
|     Nonce      |       Ciphertext       |
+----------------+------------------------+
|   N bytes      |   len(plaintext) + T   |
```

Where:
- `N` = Nonce size (cipher-dependent)
- `T` = Authentication tag size (typically 16 bytes)

The obfuscation parameters are NOT stored in the wire format. They are derived deterministically from the nonce.

## 7. Security Considerations

### 7.1 Side-Channel Mitigation

The pre-obfuscation layer provides defense-in-depth against:

- **Timing attacks**: Plaintext patterns do not influence encryption timing
- **Cache-timing attacks**: Memory access patterns are decorrelated from plaintext
- **Power analysis**: Power consumption patterns are decorrelated from plaintext structure

### 7.2 Cryptographic Security

The pre-obfuscation layer does NOT provide cryptographic security on its own. It MUST always be used in conjunction with a proper AEAD cipher. The security of the combined system relies entirely on the underlying AEAD cipher's security guarantees.

### 7.3 Entropy Requirements

The entropy source (nonce) MUST be generated using a cryptographically secure random number generator. Nonce reuse with the same key compromises both the obfuscation determinism and the AEAD security.

### 7.4 Key Stream Exhaustion

The XOR obfuscator uses SHA-256 in counter mode. For a single encryption:
- Maximum safely obfuscated data: 2^64 * 32 bytes (theoretical)
- Practical limit: Constrained by AEAD cipher limits

### 7.5 Permutation Uniqueness

The shuffle-mask obfuscator generates permutations deterministically. For data of length `n`:
- Total possible permutations: n!
- Entropy required for full permutation space: log2(n!) bits
- SHA-256 provides 256 bits, sufficient for n up to ~57 bytes without collision concerns

For larger data, the permutation space is sampled uniformly but not exhaustively.

## 8. Implementation Requirements

Conforming implementations MUST:

1. Support at least the XOR obfuscator
2. Use SHA-256 for key stream and permutation derivation
3. Use big-endian byte ordering for block numbers
4. Handle zero-length data by returning it unchanged
5. Prepend the nonce to the ciphertext output
6. Accept and process the nonce from ciphertext prefix during decryption

Conforming implementations SHOULD:

1. Support the shuffle-mask obfuscator
2. Use XChaCha20-Poly1305 as the default AEAD cipher
3. Provide constant-time implementations where feasible

## 9. Test Vectors

### 9.1 XOR Obfuscator

```
Entropy (hex): 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Plaintext (hex): 48656c6c6f2c20576f726c6421
Expected key stream prefix (hex): [first 14 bytes of SHA256(entropy || 0x0000000000000000)]
```

### 9.2 Shuffle-Mask Obfuscator

```
Entropy (hex): 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
Plaintext: "Hello"
Permutation seed: SHA256(entropy || "permutation")
Mask seed: SHA256(entropy || "mask" || 0x0000000000000000)
```

## 10. References

- [RFC 8439] ChaCha20 and Poly1305 for IETF Protocols
- [RFC 7539] ChaCha20 and Poly1305 for IETF Protocols (obsoleted by 8439)
- [draft-irtf-cfrg-xchacha] XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305
- [FIPS 180-4] Secure Hash Standard (SHA-256)
- Fisher, R. A.; Yates, F. (1948). Statistical tables for biological, agricultural and medical research

---

## Appendix A: Reference Implementation

A reference implementation in Go is available at:
`github.com/Snider/Enchantrix/pkg/enchantrix/crypto_sigil.go`

## Appendix B: Changelog

- **1.0** (2025-01-13): Initial specification
