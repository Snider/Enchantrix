# .trix File Format v2.0

The `.trix` file format is a generic and flexible binary container for storing an arbitrary data payload alongside structured metadata.

## Structure

The file is structured as follows:

| Field          | Size (bytes)     | Description                                                                                                                                                             |
|----------------|------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Magic Number**   | 4                | A constant value, `TRIX`, to identify the file as a `.trix` file.                                                                                                       |
| **Version**      | 1                | The version of the `.trix` file format (currently `2`).                                                                                                                 |
| **Header Length**| 4                | A 32-bit unsigned integer specifying the length of the JSON Header in bytes. This allows for flexible and extensible metadata.                                         |
| **JSON Header**  | `Header Length`  | A UTF-8 encoded JSON object containing metadata about the payload. Common keys include `content_type`, `encryption_algorithm`, `nonce`, `tag`, and `created_at`.      |
| **Payload**      | variable         | The raw binary data. This can be plaintext, ciphertext, or any other data. The interpretation of this data is guided by the metadata in the JSON Header.                 |

## Example JSON Header

Here is an example of what the JSON header might look like for a file encrypted with ChaCha20-Poly1305:

```json
{
  "content_type": "application/octet-stream",
  "encryption_algorithm": "chacha20poly1305",
  "nonce": "AAECAwQFBgcICQoLDA0ODxAREhMUFRY=",
  "created_at": "2025-10-30T12:00:00Z"
}
```

This decoupled design ensures that the `.trix` container is not tied to any specific encryption scheme, allowing for greater flexibility and future-proofing.

## Streaming and zero-copy access

`Encode`/`Decode` work on a `[]byte` payload, which is fine for small files
and wrong for multi-gigabyte ones. The streaming API writes the same bytes
without the payload ever being resident:

```go
// Write: payload is copied reader -> writer, never buffered.
n, err := trix.EncodeStream(header, "KVST", src, dst)

// Read: header first, then the payload as a stream.
header, payload, err := trix.DecodeHeader(f, "KVST")   // f now sits on the payload
header, n, err := trix.DecodeStream(f, "KVST", dst)    // or copy it straight out

// Locate the payload without reading a byte of it.
info, err := trix.ReadHeaderInfo(f, "KVST")
section := io.NewSectionReader(f, info.PayloadOffset, info.PayloadBytes)
```

`EncodeStream` produces output byte-for-byte identical to `Encode`, and
applies no transformation of its own — no sigil, compression, checksum or
encryption — so the binary tail remains exactly the source bytes and can be
mmap'd from `PayloadOffset`. A `checksum` recorded in the header is *not*
verified on the streaming read path, because verifying it would require
holding the whole payload; hash the stream as you consume it if you need it.
