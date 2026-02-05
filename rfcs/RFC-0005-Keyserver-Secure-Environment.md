# RFC-0005: Keyserver Secure Environment (SE)

**Status:** Standards Track
**Version:** 1.0
**Created:** 2026-02-05
**Author:** Snider

## Abstract

This document specifies the Enchantrix Keyserver, an in-process cryptographic service that holds key material and exposes operations by reference. Callers (including AI agents) interact with keys via opaque IDs and never receive raw key bytes. The specification covers the key store format, the KeyServer interface contract, the session/capability model, audit logging, and the Borg integration conventions for TIM, SMSG, and STMF.

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Key Store Format](#3-key-store-format)
4. [KeyServer Interface](#4-keyserver-interface)
5. [Session Model](#5-session-model)
6. [Audit Log Format](#6-audit-log-format)
7. [Borg Integration](#7-borg-integration)
8. [CLI Commands](#8-cli-commands)
9. [Migration Guide](#9-migration-guide)
10. [Security Considerations](#10-security-considerations)
11. [References](#11-references)

## 1. Introduction

Every crypto operation in Borg today passes raw passwords or keys directly:

- `tim.ToSigil(password)` — raw password flows to SHA-256
- `smsg.Encrypt(msg, password)` — same pattern
- `stmf.Encrypt(data, serverPublicKey)` — raw X25519 public key
- `trix.DeriveKey(password)` — SHA-256(password) with no salt/stretching

This means any caller — including AI agents — can observe raw key material in memory and in function arguments. The Keyserver Secure Environment (SE) addresses this by introducing a service boundary: callers receive an opaque key ID and perform operations by reference. The key material remains inside the keyserver.

### 1.1 Design Goals

- **Key isolation**: Raw key bytes never cross the service boundary
- **Backward compatibility**: Existing password-based APIs remain unchanged
- **Composite operations**: Format-specific encrypt/decrypt (TIM, SMSG, STMF) happen atomically inside the keyserver
- **Capability-based access**: Sessions grant specific operations on specific keys
- **Auditability**: Every crypto operation is logged
- **In-process first**: No network protocol overhead; the keyserver runs in the same Go process

### 1.2 Architecture

```
                Borg (Data Ops)                    Enchantrix (Data Security)
          ┌──────────────────────┐           ┌─────────────────────────────┐
          │  TIM · SMSG · STMF   │           │       Keyserver Service     │
          │                      │  keyID    │  ┌───────────────────────┐  │
          │  tim.ToSigilKS(h,ks) ├──────────►│  │  Key Store (Trix)     │  │
          │  smsg.EncryptKS(h,m) │  result   │  │  [master.trix]        │  │
          │  stmf.DecryptKS(h,d) │◄──────────┤  │    ├─ sym/chacha/*    │  │
          │                      │           │  │    └─ asym/x25519/*   │  │
          └──────────────────────┘           │  └───────────────────────┘  │
                                             │  ┌───────────────────────┐  │
                                             │  │  Session / ACL        │  │
                                             │  │  - capabilities       │  │
                                             │  │  - TTL, revocation    │  │
                                             │  └───────────────────────┘  │
                                             │  ┌───────────────────────┐  │
                                             │  │  Audit Logger         │  │
                                             │  │  - append-only JSONL  │  │
                                             │  └───────────────────────┘  │
                                             └─────────────────────────────┘
```

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

**Key Store**: A Trix container (magic `KEYS`) that persists encrypted key entries on disk.
**Key Entry**: A single cryptographic key with metadata (ID, type, label, creation time).
**Key ID**: An opaque hex string (16 characters) that identifies a key entry.
**KeyServer**: An in-process service backed by a Key Store that exposes crypto operations by key ID.
**Session**: A time-limited, capability-scoped authorization token.
**Capability**: A permission string in the form `operation:keyID` (e.g., `encrypt:abc123`).
**Composite Operation**: A format-specific crypto operation (e.g., `EncryptTIM`) that handles the full internal format atomically.

## 3. Key Store Format

### 3.1 Overview

The key store is itself a Trix container with magic number `KEYS`. The outer container is **not** encrypted — it stores the Argon2id salt and parameters in the header. The payload is encrypted with the master key.

```
┌─────────────────────────────────────────┐
│ Trix Container (magic: "KEYS")          │
│ ┌─────────────────────────────────────┐ │
│ │ Header (plaintext JSON)             │ │
│ │   format: "enchantrix-keystore"     │ │
│ │   version: "1.0"                    │ │
│ │   salt: <base64 bytes>              │ │
│ │   argon2_params: { ... }            │ │
│ └─────────────────────────────────────┘ │
│ ┌─────────────────────────────────────┐ │
│ │ Payload (encrypted)                 │ │
│ │   XChaCha20-Poly1305(              │ │
│ │     key: Argon2id(master, salt),    │ │
│ │     data: JSON([Entry, ...])        │ │
│ │   )                                 │ │
│ └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

### 3.2 Master Key Derivation

The master key MUST be derived using Argon2id with the following default parameters:

| Parameter | Value |
|-----------|-------|
| Time cost | 1 |
| Memory cost | 65536 (64 MB) |
| Parallelism | 4 |
| Key length | 32 bytes |
| Salt length | 16 bytes (random) |

Implementations MUST store the Argon2id parameters in the container header to support future parameter upgrades. The salt is generated randomly on first `Create` and persisted.

### 3.3 Key Entry Schema

```json
{
  "id": "a1b2c3d4e5f6a7b8",
  "type": "chacha256",
  "key_data": "<base64 encoded key bytes>",
  "label": "human-readable label",
  "created_at": "2026-02-05T12:00:00Z",
  "metadata": {
    "derived_from": "password",
    "kdf": "sha256"
  }
}
```

### 3.4 Key Types

| Type | Key Size | Description |
|------|----------|-------------|
| `chacha256` | 32 bytes | Symmetric key for ChaCha20-Poly1305 |
| `x25519` | 32 bytes (private) | X25519 Diffie-Hellman keypair |
| `hmac` | 32 bytes | HMAC-SHA256 key |
| `pgp` | variable | OpenPGP key material |

For `x25519` keys, the private key is stored in `key_data` and the public key is stored in `metadata["public_key"]` as a hex string.

### 3.5 Store Operations

| Operation | Description |
|-----------|-------------|
| `Create(path, masterPassword)` | Initialize a new store. File MUST NOT exist. |
| `Open(path, masterPassword)` | Open and decrypt existing store. |
| `Put(id, keyType, raw)` | Add a key entry. |
| `Get(id)` | Retrieve a key entry (cloned). |
| `Delete(id)` | Remove and zero key material. |
| `List()` | Return all entries with `KeyData` redacted. |
| `Import(password, label)` | Derive key via SHA-256 and store. |
| `Generate(keyType, label)` | Generate random key and store. |
| `Save()` | Persist to disk atomically (temp file + rename). |
| `Close()` | Zero master key and all key material. |

`Save()` MUST write atomically via a temporary file and rename to prevent corruption on crash.

`Close()` MUST zero all key material (master key and individual entries) before releasing memory.

`List()` MUST NOT include `KeyData` in returned entries.

### 3.6 Password Import

`Import(password, label)` derives a 32-byte key using SHA-256(password). This matches the existing `trix.DeriveKey()` behavior in Borg, ensuring backward compatibility: a password imported via the keyserver produces the same key material as the old direct-password APIs.

The original password is NEVER persisted — only the derived 32-byte key.

## 4. KeyServer Interface

### 4.1 Interface Definition

```go
type KeyServer interface {
    // Key lifecycle
    GenerateKey(ctx, keyType, label) (keyID, error)
    ImportPassword(ctx, password, label) (keyID, error)
    DeleteKey(ctx, keyID) error
    ListKeys(ctx) ([]Entry, error)
    GetPublicKey(ctx, keyID) ([]byte, error)

    // Generic crypto operations
    Encrypt(ctx, keyID, plaintext) (ciphertext, error)
    Decrypt(ctx, keyID, ciphertext) (plaintext, error)
    Sign(ctx, keyID, data) (signature, error)
    Verify(ctx, keyID, data, signature) error

    // TIM composite operations
    EncryptTIM(ctx, keyID, config, rootfs) ([]byte, error)
    DecryptTIM(ctx, keyID, payload) (config, rootfs, error)

    // SMSG composite operations
    EncryptSMSG(ctx, keyID, message) ([]byte, error)
    DecryptSMSG(ctx, keyID, ciphertext) ([]byte, error)

    // STMF operations
    DecryptSTMF(ctx, keyID, stmfData) ([]byte, error)

    // Stream key operations (SMSG V3)
    DeriveStreamKey(ctx, license, date, fingerprint) (keyID, error)
    WrapCEK(ctx, streamKeyID, cek) (wrapped, error)
    UnwrapCEK(ctx, streamKeyID, wrapped) (cek, error)
}
```

### 4.2 Composite Operations

Composite operations exist because Borg's data formats have internal structure that requires multiple encrypt/decrypt passes with the same key. Rather than exposing the key for multiple calls, the keyserver performs the entire format-specific operation atomically.

**EncryptTIM**: Encrypts config and rootfs separately using the same ChaChaPolySigil instance, then packs them into the TIM binary layout: `[4-byte config_size][encrypted_config][encrypted_rootfs]`.

**DecryptTIM**: Reads the TIM binary layout, decrypts both components, returns them separately.

**EncryptSMSG / DecryptSMSG**: Encrypts/decrypts the SMSG message payload using ChaCha20-Poly1305 with the password-derived key.

**DecryptSTMF**: Performs X25519 ECDH with the server's private key and the client's ephemeral public key (extracted from the STMF header), derives the shared symmetric key, and decrypts the form data. The server's private key never leaves the keyserver.

### 4.3 Stream Key Operations

For SMSG V3 (rolling license-based keys):

1. `DeriveStreamKey(license, date, fingerprint)` computes `SHA256(LTHN(date:license:fingerprint))` and stores the result as a temporary key entry. Returns a key ID.

2. `WrapCEK(streamKeyID, cek)` encrypts the per-message Content Encryption Key (CEK) with the stream key using ChaCha20-Poly1305. Returns base64-encoded wrapped CEK.

3. `UnwrapCEK(streamKeyID, wrapped)` reverses the wrapping.

Callers MUST delete temporary stream keys after use via `DeleteKey`.

## 5. Session Model

### 5.1 Session Structure

```json
{
  "id": "ses_a1b2c3d4e5f6a7b8...",
  "capabilities": [
    {"operation": "encrypt", "key_id": "abc123"},
    {"operation": "decrypt", "key_id": "abc123"}
  ],
  "created_at": "2026-02-05T12:00:00Z",
  "expires_at": "2026-02-05T13:00:00Z",
  "client_id": "agent-worker-1"
}
```

### 5.2 Capability Format

A capability is a string in the form `operation:keyID`.

**Valid operations**: `encrypt`, `decrypt`, `sign`, `verify`, `list`, `derive`, `delete`, `generate`, `import`, `wrap`, `unwrap`.

**Key ID**: A specific key ID, or `*` as a wildcard matching all keys.

Examples:
- `encrypt:abc123` — can encrypt with key abc123
- `decrypt:*` — can decrypt with any key
- `list:*` — can list keys

### 5.3 Session Lifecycle

1. `CreateSession(clientID, capabilities, ttl)` creates a session with a random 128-bit ID (prefixed `ses_`).
2. `ValidateSession(sessionID, op, keyID)` checks existence, expiry, revocation, and capability match.
3. `RevokeSession(sessionID)` immediately invalidates the session.
4. `CleanExpired()` removes expired sessions from memory.

A session MUST be rejected if:
- It does not exist
- It has been revoked
- It has expired (current time > ExpiresAt)
- It lacks a matching capability for the requested operation

### 5.4 Security Properties

- Session IDs are 128-bit random values (cryptographically strong)
- Sessions are in-memory only (not persisted across restarts)
- Revocation is immediate (checked on every operation)
- No session refreshing — create a new session when needed

## 6. Audit Log Format

### 6.1 Event Schema

Each crypto operation produces a JSONL event:

```json
{
  "ts": "2026-02-05T12:00:00.123456Z",
  "session_id": "ses_abc...",
  "op": "encrypt",
  "key_id": "abc123",
  "ok": true,
  "error": "",
  "input_size": 1024
}
```

| Field | Type | Description |
|-------|------|-------------|
| `ts` | RFC 3339 timestamp | When the operation occurred |
| `session_id` | string | Session that requested the operation (may be empty) |
| `op` | string | Operation name (encrypt, decrypt, sign, etc.) |
| `key_id` | string | Key ID used |
| `ok` | bool | Whether the operation succeeded |
| `error` | string | Error message if failed |
| `input_size` | int | Size of input data (not the data itself) |

### 6.2 Storage

- Audit events are written as append-only JSONL (one JSON object per line)
- File permissions MUST be 0600
- Events MUST NOT contain key material, plaintext, or ciphertext
- Only the size of the input is logged
- The audit log supports memory-only mode for testing

### 6.3 Querying

The audit log supports filtering by:
- Time range (`since`, `until`)
- Session ID
- Operation
- Key ID

## 7. Borg Integration

### 7.1 TIM Integration

New keyserver-aware functions are added alongside existing APIs:

```go
// Existing (unchanged)
func (m *TIM) ToSigil(password string) ([]byte, error)
func FromSigil(data []byte, password string) (*TIM, error)

// New keyserver variants
func (m *TIM) ToSigilKS(ctx, keyID, ks) ([]byte, error)
func FromSigilKS(data, keyID, ks) (*TIM, error)
func NewCacheKS(dir, keyID, ks) (*CacheKS, error)
func RunEncryptedKS(ctx, stimPath, keyID, ks) error
```

**Format compatibility**: `ToSigilKS` produces identical STIM containers to `ToSigil` when the same derived key is used (via `ImportPassword`). This means a file encrypted with the keyserver can be decrypted with the old password API and vice versa.

### 7.2 SMSG Integration

```go
// V1/V2: keyserver holds the password-derived key
func EncryptKS(ctx, msg, keyID, ks) ([]byte, error)
func DecryptKS(ctx, data, keyID, ks) (*Message, error)

// V3: stream keys derived and CEK wrapped via keyserver
func EncryptV3KS(ctx, msg, params, manifest, ks) ([]byte, error)
func DecryptV3KS(ctx, data, params, ks) (*Message, *Header, error)
```

**V3 flow**:
1. `EncryptV3KS` generates a random CEK (ephemeral, per-message)
2. Derives stream keys for current and next rolling periods via `ks.DeriveStreamKey()`
3. Wraps CEK with each stream key via `ks.WrapCEK()`
4. Encrypts message content with CEK locally (CEK is ephemeral, not a long-lived secret)
5. Deletes temporary stream keys

### 7.3 STMF Integration

```go
// Client-side (unchanged — uses raw public key)
func Encrypt(data *FormData, serverPublicKey []byte) ([]byte, error)

// Server-side via keyserver
func DecryptKS(ctx, stmfData, keyID, ks) (*FormData, error)
func GenerateKeyPairKS(ctx, label, ks) (publicKey, keyID, error)
```

The client encrypts using the server's X25519 public key (distributed out-of-band). The server decrypts via the keyserver, which performs ECDH internally — the server's private key never leaves the keyserver.

**Key rotation**: `GenerateKeyPairKS` creates new keypairs. Old keypairs remain in the store and can still decrypt old form submissions. New forms use the new public key.

## 8. CLI Commands

### 8.1 Key Store Management

```bash
# Initialize a new key store
trix keystore init --path ~/.enchantrix/keys.trix
# (reads master password from stdin or ENCHANTRIX_MASTER env)

# Import a password as a named key
trix keystore import --path keys.trix --label "borg-tim-key"
# (reads master password, then import password from stdin)

# Generate a new random key
trix keystore generate --path keys.trix --label "stmf-server" --type x25519

# List stored keys (no key material shown)
trix keystore list --path keys.trix

# Delete a key
trix keystore delete --path keys.trix --id <key-id>
```

### 8.2 Keyserver Management

```bash
# Start keyserver (blocks until Ctrl+C)
trix keyserver start --store keys.trix --addr :9100

# Create a session token
trix keyserver session create --store keys.trix \
  --caps "encrypt:key-abc,decrypt:key-abc" --ttl 1h --client agent-1
```

### 8.3 Password Input

Passwords MUST NOT be passed via CLI flags (to avoid shell history exposure). The CLI reads passwords from:

1. `ENCHANTRIX_MASTER` environment variable (for the master password)
2. stdin (prompted with "Master password: " or "Password to import: ")

## 9. Migration Guide

### 9.1 Before (Password-Based)

```go
// TIM
stim, _ := tim.ToSigil("my-password")
restored, _ := tim.FromSigil(stim, "my-password")

// SMSG
encrypted, _ := smsg.Encrypt(msg, "my-password")
decrypted, _ := smsg.Decrypt(encrypted, "my-password")

// STMF
pub, priv, _ := stmf.GenerateKeyPair()
encrypted, _ := stmf.Encrypt(formData, pub)
decrypted, _ := stmf.Decrypt(encrypted, priv)
```

### 9.2 After (Keyserver-Based)

```go
// One-time setup
store, _ := keystore.Open("keys.trix", masterPassword)
ks := keyserver.NewServer(store)

// Import existing password (produces same derived key)
keyID, _ := ks.ImportPassword(ctx, "my-password", "tim-key")

// TIM — password never visible
stim, _ := tim.ToSigilKS(ctx, keyID, ks)
restored, _ := tim.FromSigilKS(stim, keyID, ks)

// SMSG — password never visible
encrypted, _ := smsg.EncryptKS(ctx, msg, keyID, ks)
decrypted, _ := smsg.DecryptKS(ctx, encrypted, keyID, ks)

// STMF — private key generated and held by keyserver
pub, stmfKeyID, _ := stmf.GenerateKeyPairKS(ctx, "stmf-server", ks)
encrypted, _ := stmf.Encrypt(formData, pub)  // client unchanged
decrypted, _ := stmf.DecryptKS(ctx, encrypted, stmfKeyID, ks)
```

### 9.3 Interoperability

Files encrypted with the old API can be decrypted with the keyserver API (and vice versa) as long as the same password was imported. This is guaranteed because `ImportPassword` uses `SHA256(password)` — the same derivation as `trix.DeriveKey()`.

## 10. Security Considerations

### 10.1 Threat Model

**In scope**:
- AI agents that should perform crypto operations but MUST NOT see key material
- Multi-tenant environments where callers need scoped access to specific keys
- Audit compliance requiring operation logging

**Out of scope** (future work):
- Memory forensics attacks (require HSM integration)
- Side-channel attacks on the Argon2id derivation
- Network transport security (keyserver is in-process)

### 10.2 Key Material Lifecycle

1. **At rest**: Keys are encrypted inside a Trix container with Argon2id-derived master key
2. **In memory**: Keys are decrypted when the store is opened and held in Go heap memory
3. **On delete**: Key bytes are zeroed before removal from the map
4. **On close**: Master key and all entry key material are zeroed

### 10.3 Password Handling

- Master passwords are never persisted (only the derived key via Argon2id)
- Imported passwords are never persisted (only SHA-256 derived key)
- CLI reads passwords from stdin, not flags (avoids shell history)
- The `ENCHANTRIX_MASTER` env var is an acceptable alternative for automated environments

### 10.4 Session Security

- Session IDs are 128-bit cryptographically random values
- Sessions are in-memory only — not persisted across process restarts
- Expired and revoked sessions are rejected immediately
- Wildcard capabilities (`decrypt:*`) should be granted sparingly

### 10.5 Audit Log Integrity

- The audit log is append-only with 0600 permissions
- Audit events contain operation metadata, not data content
- Input sizes are logged for anomaly detection
- Deletion of audit records is not supported by the API

### 10.6 Backward Compatibility Risks

The `ImportPassword` function uses SHA-256 to match Borg's existing `DeriveKey`. SHA-256 is a fast hash unsuitable for password derivation. This is a conscious trade-off for backward compatibility. For new deployments without legacy data, `Generate` with random keys is RECOMMENDED.

## 11. References

- RFC-0001: Pre-Obfuscation Layer
- RFC-0002: Trix Container Format
- RFC-0003: Sigil Transformation Framework
- RFC-0004: LTHN Hash Algorithm
- [RFC 2119] Key words for use in RFCs to Indicate Requirement Levels
- [RFC 9106] Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications

---

## Appendix A: Magic Number Registration

This RFC registers the following magic number (per RFC-0002 Section 8):

| Magic | Application | Description |
|-------|-------------|-------------|
| `KEYS` | Enchantrix | Encrypted key store container |

## Appendix B: Key Store Binary Layout

```
┌─────────────────────────────────────────────────────┐
│ "KEYS" │ 0x02 │ HdrLen │ JSON Header │ Payload     │
│  (4B)  │ (1B) │  (4B)  │   (var)     │   (var)     │
└─────────────────────────────────────────────────────┘

Header:
  { "format": "enchantrix-keystore",
    "version": "1.0",
    "salt": "<base64>",
    "argon2_params": "{\"time\":1,\"memory\":65536,...}" }

Payload = XChaCha20-Poly1305(
  key:  Argon2id(masterPassword, salt, params),
  data: JSON([ Entry, Entry, ... ])
)
```

## Appendix C: Capability String Grammar

```
capability    = operation ":" key-selector
operation     = "encrypt" | "decrypt" | "sign" | "verify"
              | "list" | "derive" | "delete" | "generate"
              | "import" | "wrap" | "unwrap"
key-selector  = key-id | "*"
key-id        = 1*HEXDIG

capabilities  = capability *("," capability)
```

## Appendix D: Reference Implementation

- Key Store: `github.com/Snider/Enchantrix/pkg/keystore/`
- KeyServer: `github.com/Snider/Enchantrix/pkg/keyserver/`
- CLI: `github.com/Snider/Enchantrix/cmd/trix/` (keystore.go, keyserver.go)
- Borg TIM integration: `github.com/Snider/Borg/pkg/tim/keyserver.go`
- Borg SMSG integration: `github.com/Snider/Borg/pkg/smsg/keyserver.go`
- Borg STMF integration: `github.com/Snider/Borg/pkg/stmf/keyserver.go`

## Appendix E: Changelog

- **1.0** (2026-02-05): Initial specification
