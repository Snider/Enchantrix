# CLI Reference

The `trix` command-line tool allows you to work with `.trix` files, apply sigils, and perform hashing operations directly from the terminal.

## Usage

```bash
trix [command]
```

## Global Flags

*   `--help`: Show help for command.

## Commands

### `encode`

Encodes data into the `.trix` file format.

```bash
trix encode [flags] [sigils...]
```

**Flags:**

*   `-i, --input string`: Input file path. If not specified, reads from stdin.
*   `-o, --output string`: Output file path. If not specified, writes to stdout.
*   `-m, --magic string`: Custom 4-byte magic number (e.g., `TRIX`).

**Example:**

```bash
# Encode a file, apply gzip and base64 sigils, and save to output.trix
trix encode -i data.json -o output.trix -m TRIX gzip base64
```

### `decode`

Decodes a `.trix` file.

```bash
trix decode [flags] [sigils...]
```

**Flags:**

*   `-i, --input string`: Input file path. If not specified, reads from stdin.
*   `-o, --output string`: Output file path. If not specified, writes to stdout.
*   `-m, --magic string`: Custom 4-byte magic number.

**Example:**

```bash
# Decode a file, reversing the base64 and gzip sigils implicitly if stored in header,
# or explicit sigils can be passed if needed for unpacking steps not in header (though unlikely for standard use).
# Typically:
trix decode -i output.trix -o restored.json -m TRIX
```

### `hash`

Hashes input data using a specified algorithm.

```bash
trix hash [algorithm] [flags]
```

**Arguments:**

*   `algorithm`: The hash algorithm to use (e.g., `sha256`, `md5`, `lthn`).

**Flags:**

*   `-i, --input string`: Input file path. If not specified, reads from stdin.

**Example:**

```bash
echo "hello" | trix hash sha256
```

### Sigil Commands

You can apply individual sigils directly to data.

```bash
trix [sigil_name] [flags]
```

**Available Sigils:**

*   `reverse`
*   `hex`
*   `base64`
*   `gzip`
*   `json`, `json-indent`
*   `md4`, `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`
*   `ripemd160`
*   `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`
*   `sha512-224`, `sha512-256`
*   `blake2s-256`, `blake2b-256`, `blake2b-384`, `blake2b-512`

**Flags:**

*   `-i, --input string`: Input file or string. Use `-` for stdin.

**Example:**

```bash
# Base64 encode a string
trix base64 -i "hello world"

# Gzip a file
trix gzip -i myfile.txt > myfile.txt.gz
```
