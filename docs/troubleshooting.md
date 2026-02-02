# Troubleshooting

This page provides solutions to common problems you might encounter while using Enchantrix.

## CLI

### `command not found: trix`

This error means that the `trix` binary is not in your system's `PATH`. When you install Go binaries with `go install`, they are placed in the `GOBIN` directory, which is typically `$GOPATH/bin`.

To fix this, you need to add your Go binary path to your shell's `PATH` variable. Add the following line to your shell's configuration file (e.g., `~/.bashrc`, `~/.zshrc`):

```sh
export PATH=$PATH:$(go env GOPATH)/bin
```

Then, restart your shell or source the configuration file for the changes to take effect.

## Library

### `trix: invalid magic number`

This error occurs when you try to decode a `.trix` file with a magic number that does not match the one that was used to encode it. The magic number is a 4-byte string that acts as a file format identifier.

To fix this, ensure that you are using the same magic number for both `trix.Encode()` and `trix.Decode()`.

### `trix: checksum mismatch`

This error indicates that the payload of the `.trix` container has been corrupted or altered since it was created. The checksum is a hash of the payload that is stored in the header to verify data integrity.

If you encounter this error, the data you are trying to read is not the same as the data that was originally written.
