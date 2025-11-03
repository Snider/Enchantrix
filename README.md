# Enchantrix

[![codecov](https://codecov.io/github/Snider/Enchantrix/branch/main/graph/badge.svg?token=2E1QWEDFUW)](https://codecov.io/github/Snider/Enchantrix)

Enchantrix is a Go-based encryption library for the Core framework, designed to provide a secure and easy-to-use framework for handling sensitive data in Web3 applications. It will feature Poly-ChaCha stream proxying and a custom `.trix` file format for encrypted data.

## Test-Driven Development

This project follows a strict Test-Driven Development (TDD) methodology. All new functionality must be accompanied by a comprehensive suite of tests.

## Getting Started

To get started with Enchantrix, you'll need to have Go installed. You can then run the tests using the following command:

```shell
go test ./...
```

## `trix` Command-Line Tool

Enchantrix includes a command-line tool called `trix` for encoding and decoding files using the `.trix` format.

### Installation

You can install the `trix` tool using `go install`:

```shell
go install github.com/Snider/Enchantrix/cmd/trix@latest
```

### Usage

The `trix` tool can read from a file using the `--input` flag or from `stdin` if the flag is omitted.

#### Encode

To encode a file, use the `encode` subcommand, followed by any sigils you want to apply:

```shell
trix encode --output <output-file> --magic <magic-number> [sigil1] [sigil2]...
```

- `--input`: The path to the input file (optional, reads from stdin if omitted).
- `--output`: The path to the output `.trix` file.
- `--magic`: A 4-byte magic number to identify the file type.
- `[sigil...]`: A space-separated list of sigils to apply to the data.

Example:
```shell
echo "Hello, Trix!" | trix encode --output test.trix --magic TRIX base64
```

#### Decode

To decode a `.trix` file, use the `decode` subcommand:

```shell
trix decode --output <output-file> --magic <magic-number> [sigil1] [sigil2]...
```

- `--input`: The path to the input `.trix` file (optional, reads from stdin if omitted).
- `--output`: The path to the decoded output file.
- `--magic`: The 4-byte magic number used during encoding.
- `[sigil...]`: A space-separated list of sigils to apply for unpacking.

Example:
```shell
trix decode --input test.trix --output test.txt --magic TRIX base64
```

#### Hash

To hash data, use the `hash` subcommand, followed by the desired algorithm:

```shell
trix hash [algorithm]
```

- `--input`: The path to the input file (optional, reads from stdin if omitted).
- `[algorithm]`: The hashing algorithm to use (e.g., `sha256`).

Example:
```shell
echo "Hello, Trix!" | trix hash sha256
```

#### Sigils

You can also apply any sigil directly as a subcommand:

```shell
trix [sigil]
```

- `--input`: The path to the input file or a string (optional, reads from stdin if omitted).

Example:
```shell
echo "Hello, Trix!" | trix hex
```
