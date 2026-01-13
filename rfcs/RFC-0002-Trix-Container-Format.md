# RFC-0002: TRIX Binary Container Format

**Status:** Standards Track
**Version:** 2.0
**Created:** 2025-01-13
**Author:** Snider

## Abstract

This document specifies the TRIX binary container format, a generic and extensible file format designed to store arbitrary binary payloads alongside structured JSON metadata. The format is protocol-agnostic, supporting any encryption scheme, compression algorithm, or data transformation while providing a consistent structure for metadata discovery and payload extraction.

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Format Specification](#3-format-specification)
4. [Header Specification](#4-header-specification)
5. [Encoding Process](#5-encoding-process)
6. [Decoding Process](#6-decoding-process)
7. [Checksum Verification](#7-checksum-verification)
8. [Magic Number Registry](#8-magic-number-registry)
9. [Security Considerations](#9-security-considerations)
10. [IANA Considerations](#10-iana-considerations)
11. [References](#11-references)

## 1. Introduction

The TRIX format addresses the need for a simple, self-describing binary container that can wrap any payload type with extensible metadata. Unlike format-specific containers (such as encrypted archive formats), TRIX separates the concerns of:

- **Container structure**: How data is organized on disk/wire
- **Payload semantics**: What the payload contains and how to process it
- **Metadata extensibility**: Application-specific attributes

### 1.1 Design Goals

- **Simplicity**: Minimal overhead, easy to implement
- **Extensibility**: JSON header allows arbitrary metadata
- **Protocol-agnostic**: No assumptions about payload encryption or encoding
- **Streaming-friendly**: Header length prefix enables streaming reads
- **Magic-number customizable**: Applications can define their own identifiers

### 1.2 Use Cases

- Encrypted data interchange
- Signed document containers
- Configuration file packaging
- Backup archive format
- Inter-service message envelopes

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

**Container**: A complete TRIX-formatted byte sequence
**Magic Number**: A 4-byte identifier at the start of the container
**Header**: A JSON object containing metadata about the payload
**Payload**: The arbitrary binary data stored in the container
**Checksum**: An optional integrity verification value

## 3. Format Specification

### 3.1 Overview

A TRIX container consists of five sequential fields:

```
+----------------+---------+---------------+----------------+-----------+
| Magic Number   | Version | Header Length | JSON Header    | Payload   |
+----------------+---------+---------------+----------------+-----------+
|    4 bytes     | 1 byte  |    4 bytes    | Variable       | Variable  |
```

Total minimum size: 9 bytes (empty header, empty payload)

### 3.2 Field Definitions

#### 3.2.1 Magic Number (4 bytes)

A 4-byte ASCII string identifying the file type. This field:

- MUST be exactly 4 bytes
- SHOULD contain printable ASCII characters
- Is application-defined (not mandated by this specification)

Common conventions:
- `TRIX` - Generic TRIX container
- First character uppercase, application-specific identifier

#### 3.2.2 Version (1 byte)

An unsigned 8-bit integer indicating the format version.

| Value | Description |
|-------|-------------|
| 0x00 | Reserved |
| 0x01 | Version 1.0 (deprecated) |
| 0x02 | Version 2.0 (current) |
| 0x03-0xFF | Reserved for future versions |

Implementations MUST reject containers with unrecognized versions.

#### 3.2.3 Header Length (4 bytes)

A 32-bit unsigned integer in big-endian byte order specifying the length of the JSON Header in bytes.

- Minimum value: 0 (empty header represented as `{}` is 2 bytes, but 0 is valid)
- Maximum value: 16,777,215 (16 MB - 1 byte)

Implementations MUST reject headers exceeding 16 MB to prevent denial-of-service attacks.

```
Header Length = BigEndian32(length_of_json_header_bytes)
```

#### 3.2.4 JSON Header (Variable)

A UTF-8 encoded JSON object containing metadata. The header:

- MUST be valid JSON (RFC 8259)
- MUST be a JSON object (not array, string, or primitive)
- SHOULD use UTF-8 encoding without BOM
- MAY be empty (`{}`)

#### 3.2.5 Payload (Variable)

The arbitrary binary payload. The payload:

- MAY be empty (zero bytes)
- MAY contain any binary data
- Length is implicitly determined by: `container_length - 9 - header_length`

## 4. Header Specification

### 4.1 Reserved Header Fields

The following header fields have defined semantics:

| Field | Type | Description |
|-------|------|-------------|
| `content_type` | string | MIME type of the payload (before any transformations) |
| `checksum` | string | Hex-encoded checksum of the payload |
| `checksum_algo` | string | Algorithm used for checksum (e.g., "sha256") |
| `created_at` | string | ISO 8601 timestamp of creation |
| `encryption_algorithm` | string | Encryption algorithm identifier |
| `compression` | string | Compression algorithm identifier |
| `sigils` | array | Ordered list of transformation sigil names |

### 4.2 Extension Fields

Applications MAY include additional fields. To avoid conflicts:

- Custom fields SHOULD use a namespace prefix (e.g., `x-myapp-field`)
- Standard field names are lowercase with underscores

### 4.3 Example Headers

#### Encrypted payload:
```json
{
  "content_type": "application/octet-stream",
  "encryption_algorithm": "xchacha20poly1305",
  "created_at": "2025-01-13T12:00:00Z"
}
```

#### Compressed and encoded payload:
```json
{
  "content_type": "text/plain",
  "compression": "gzip",
  "sigils": ["gzip", "base64"],
  "checksum": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
  "checksum_algo": "sha256"
}
```

#### Minimal header:
```json
{}
```

## 5. Encoding Process

### 5.1 Algorithm

```
function Encode(payload: bytes, header: object, magic: string) -> bytes:
    // Validate magic number
    if length(magic) != 4:
        return error("magic number must be 4 bytes")

    // Serialize header to JSON
    header_bytes = JSON.serialize(header)
    header_length = length(header_bytes)

    // Validate header size
    if header_length > 16777215:
        return error("header exceeds maximum size")

    // Build container
    container = empty byte buffer

    // Write magic number (4 bytes)
    container.write(magic)

    // Write version (1 byte)
    container.write(0x02)

    // Write header length (4 bytes, big-endian)
    container.write(BigEndian32(header_length))

    // Write JSON header
    container.write(header_bytes)

    // Write payload
    container.write(payload)

    return container.bytes()
```

### 5.2 Checksum Integration

If integrity verification is required:

```
function EncodeWithChecksum(payload: bytes, header: object, magic: string, algo: string) -> bytes:
    checksum = Hash(algo, payload)
    header["checksum"] = HexEncode(checksum)
    header["checksum_algo"] = algo
    return Encode(payload, header, magic)
```

## 6. Decoding Process

### 6.1 Algorithm

```
function Decode(container: bytes, expected_magic: string) -> (header: object, payload: bytes):
    // Validate minimum size
    if length(container) < 9:
        return error("container too small")

    // Read and verify magic number
    magic = container[0:4]
    if magic != expected_magic:
        return error("invalid magic number")

    // Read and verify version
    version = container[4]
    if version != 0x02:
        return error("unsupported version")

    // Read header length
    header_length = BigEndian32(container[5:9])

    // Validate header length
    if header_length > 16777215:
        return error("header length exceeds maximum")

    if length(container) < 9 + header_length:
        return error("container truncated")

    // Read and parse header
    header_bytes = container[9:9+header_length]
    header = JSON.parse(header_bytes)

    // Read payload
    payload = container[9+header_length:]

    return (header, payload)
```

### 6.2 Streaming Decode

For large files, streaming decode is RECOMMENDED:

```
function StreamDecode(reader: Reader, expected_magic: string) -> (header: object, payload_reader: Reader):
    // Read fixed-size prefix
    prefix = reader.read(9)

    // Validate magic and version
    magic = prefix[0:4]
    version = prefix[4]
    header_length = BigEndian32(prefix[5:9])

    // Read header
    header_bytes = reader.read(header_length)
    header = JSON.parse(header_bytes)

    // Return remaining reader for payload streaming
    return (header, reader)
```

## 7. Checksum Verification

### 7.1 Supported Algorithms

| Algorithm ID | Output Size | Notes |
|--------------|-------------|-------|
| `md5` | 16 bytes | NOT RECOMMENDED for security |
| `sha1` | 20 bytes | NOT RECOMMENDED for security |
| `sha256` | 32 bytes | RECOMMENDED |
| `sha384` | 48 bytes | |
| `sha512` | 64 bytes | |
| `blake2b-256` | 32 bytes | |
| `blake2b-512` | 64 bytes | |

### 7.2 Verification Process

```
function VerifyChecksum(header: object, payload: bytes) -> bool:
    if "checksum" not in header:
        return true  // No checksum to verify

    algo = header["checksum_algo"]
    expected = HexDecode(header["checksum"])
    actual = Hash(algo, payload)

    return constant_time_compare(expected, actual)
```

## 8. Magic Number Registry

This section defines conventions for magic number allocation:

### 8.1 Reserved Magic Numbers

| Magic | Reserved For |
|-------|--------------|
| `TRIX` | Generic TRIX containers |
| `\x00\x00\x00\x00` | Reserved (null) |
| `\xFF\xFF\xFF\xFF` | Reserved (test/invalid) |

### 8.2 Allocation Guidelines

Applications SHOULD:

1. Use 4 printable ASCII characters
2. Start with an uppercase letter
3. Avoid common file format magic numbers (e.g., `%PDF`, `PK\x03\x04`)
4. Register custom magic numbers in their documentation

## 9. Security Considerations

### 9.1 Header Injection

The JSON header is parsed before processing. Implementations MUST:

- Validate JSON syntax strictly
- Reject headers with duplicate keys
- Not execute header field values as code

### 9.2 Denial of Service

The 16 MB header limit prevents memory exhaustion attacks. Implementations SHOULD:

- Reject headers before full allocation if length exceeds limit
- Implement timeouts for header parsing
- Limit recursion depth in JSON parsing

### 9.3 Path Traversal

Header fields like `filename` MUST NOT be used directly for filesystem operations without sanitization.

### 9.4 Checksum Security

- MD5 and SHA1 checksums provide integrity but not authenticity
- For tamper detection, use HMAC or digital signatures
- Checksum verification MUST use constant-time comparison

### 9.5 Version Negotiation

Implementations MUST NOT attempt to parse containers with unknown versions, as the format may change incompatibly.

## 10. IANA Considerations

This document does not require IANA actions. The TRIX format is application-defined and does not use IANA-managed namespaces.

Future versions may define:
- Media type registration (e.g., `application/x-trix`)
- Magic number registry

## 11. References

- [RFC 8259] The JavaScript Object Notation (JSON) Data Interchange Format
- [RFC 2119] Key words for use in RFCs to Indicate Requirement Levels
- [RFC 6838] Media Type Specifications and Registration Procedures

---

## Appendix A: Binary Layout Diagram

```
Byte offset:  0         4    5         9         9+H       9+H+P
              |---------|----|---------|---------|---------|
              | Magic   | V  | HdrLen  | Header  | Payload |
              | (4)     |(1) | (4)     | (H)     | (P)     |
              |---------|----|---------|---------|---------|

V = Version byte
H = Header length (from HdrLen field)
P = Payload length (remaining bytes)
```

## Appendix B: Reference Implementation

A reference implementation in Go is available at:
`github.com/Snider/Enchantrix/pkg/trix/trix.go`

## Appendix C: Changelog

- **2.0** (2025-01-13): Current version with JSON header
- **1.0** (deprecated): Initial version with fixed header fields
