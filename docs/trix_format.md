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
