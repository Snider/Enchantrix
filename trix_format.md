# .trix File Format

The `.trix` file format is a binary format for storing encrypted data.

## Structure

The file is structured as follows:

| Field | Size (bytes) | Description |
|---|---|---|
| Magic Number | 4 | A constant value, `TRIX`, to identify the file as a `.trix` file. |
| Version | 1 | The version of the `.trix` file format. |
| Algorithm | 1 | The encryption algorithm used. |
| Nonce | 24 | The nonce used for encryption. |
| Ciphertext | variable | The encrypted data. |

## Algorithm IDs

| ID | Algorithm |
|---|---|
| 1 | ChaCha20-Poly1305 |
