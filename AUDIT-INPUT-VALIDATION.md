# Security Audit: Input Validation

This document outlines the results of a security audit focused on input validation and sanitization within the Enchantrix project.

## 1. Input Entry Points Inventory

Untrusted input can enter the system through the following channels:

### a. Command-Line Interface (`trix` CLI)
- **Description**: The primary user-facing tool for interacting with the `.trix` format.
- **Entry Points**:
  - **Arguments**: Positional arguments are used for sigil names (`trix encode base64`) and the hash algorithm (`trix hash sha256`).
  - **Flags**: Flags like `--input`, `--output`, and `--magic` provide file paths and configuration values.
  - **Standard Input (stdin)**: The CLI reads data from stdin when the `--input` flag is omitted or set to `-`.

### b. `.trix` File Format
- **Description**: A binary container format for storing metadata and a payload.
- **Entry Points**:
  - **Magic Number (4 bytes)**: A user-defined identifier.
  - **Header Length (4 bytes)**: An integer specifying the size of the JSON header.
  - **JSON Header**: A metadata block that is unmarshaled into a `map[string]interface{}`. This is a significant entry point for structured, untrusted data.
  - **Payload**: Arbitrary binary data.

### c. Function Parameters in Public APIs
- **Description**: The public functions in the `pkg/` directories can be consumed by other Go applications, making their parameters an entry point.
- **Entry Points**:
  - `trix.Decode(data []byte, ...)`: `data` is the raw, untrusted byte stream of a `.trix` file.
  - `enchantrix.NewSigil(name string)`: The `name` string determines which sigil is created.
  - `crypt.Service.Hash(lib HashType, payload string)`: `lib` and `payload` are user-provided.
  - `crypt.Service` methods for RSA and PGP accept keys and data as byte slices.

---

## 2. Validation Gaps Found

The audit identified the following gaps in the current input validation mechanisms.

### Gap 1: Unstructured JSON Header Parsing (DoS/Type Confusion)
- **Vulnerability**: The `trix.Decode` function parses the JSON header into a `map[string]interface{}`. This provides no structure or type safety. An attacker can craft a header with unexpected data types (e.g., an array instead of a string for `checksum_algo`).
- **Impact**: Subsequent code that performs type assertions on these map values (e.g., `header["encrypted"].(bool)`) will panic if the type is incorrect, leading to a **Denial of Service (DoS)**.

### Gap 2: Resource Exhaustion via Gzip Decompression (Decompression Bomb)
- **Vulnerability**: The `enchantrix.GzipSigil.Out` method reads the entire decompressed stream into memory without any limits (`io.ReadAll(r)`).
- **Impact**: An attacker can create a small, highly-compressed file (a "decompression bomb") that, when decompressed, expands to an extremely large size. This will exhaust all available memory, causing a **Denial of Service (DoS)**.

### Gap 3: Insufficient Validation on File Paths
- **Vulnerability**: The CLI tool accepts file paths via the `--input` and `--output` flags. There is no validation to prevent path traversal attacks (`../../..`).
- **Impact**: While the immediate risk is low since the tool is user-run, if it were ever used in an automated or server-side context, an attacker could potentially read or overwrite arbitrary files on the system.

### Gap 4: Information Leak in Error Messages
- **Vulnerability**: The error message for an invalid magic number in `trix.Decode` reveals both the expected and received values (`fmt.Errorf("%w: expected %s, got %s", ...)`).
- **Impact**: This provides minor but unnecessary information to an attacker about the file format's internal structure.

---

## 3. Injection Vectors Discovered

Based on the identified gaps, the following injection vectors exist:

- **DoS via Malformed Header**: Craft a `.trix` file with a JSON header containing invalid value types for keys like `encrypted` or `checksum_algo`. When the `trix` CLI or any service using `trix.Decode` attempts to process this file, it will crash.
- **DoS via Decompression Bomb**: Craft a compressed `.trix` file using the `gzip` sigil. Feed this file to the `trix decode gzip` command. The process will consume excessive memory and crash.
- **Path Traversal**: While not an "injection" in the traditional sense, providing an output path like `/etc/passwd` to the `trix encode` command on a system with improper permissions could lead to file corruption.

---

## 4. Remediation Recommendations

The following actions are recommended to close the identified validation gaps.

### a. Remediate Unstructured JSON Header
- **Recommendation**: Replace the `map[string]interface{}` with a strictly-typed `Header` struct. Use this struct as the target for `json.Unmarshal`. This enforces schema validation at the parsing stage.
- **Code Example (`pkg/trix/trix.go`)**:

```go
// Create a new Header struct
type Header struct {
    Checksum     string `json:"checksum,omitempty"`
    ChecksumAlgo string `json:"checksum_algo,omitempty"`
    Encrypted    bool   `json:"encrypted,omitempty"`
    // Add other expected header fields here...
}

// Update the Trix struct
type Trix struct {
    Header  Header // Use the struct instead of map
    Payload []byte
    // ... rest of the struct
}

// In trix.Decode function:
// ...
var header Header // Use the new struct type
if err := json.Unmarshal(headerBytes, &header); err != nil {
    return nil, err // Let the JSON parser handle validation
}
// ...
```

### b. Remediate Gzip Decompression Bomb
- **Recommendation**: Use an `io.LimitedReader` to restrict the amount of data that can be read from the gzip stream, preventing memory exhaustion.
- **Code Example (`pkg/enchantrix/sigils.go`)**:

```go
// In GzipSigil.Out method:
func (s *GzipSigil) Out(data []byte) ([]byte, error) {
    if data == nil {
        return nil, nil
    }
    r, err := gzip.NewReader(bytes.NewReader(data))
    if err != nil {
        return nil, err
    }
    defer r.Close()

    // Limit the output to a reasonable size, e.g., 32MB
    const maxDecompressedSize = 32 * 1024 * 1024
    limitedReader := &io.LimitedReader{R: r, N: maxDecompressedSize}

    decompressedData, err := io.ReadAll(limitedReader)
    if err != nil {
        return nil, err
    }

    // Check if the limit was reached
    if limitedReader.N == 0 {
        return nil, errors.New("enchantrix: decompressed data exceeds size limit")
    }

    return decompressedData, nil
}
```

### c. Remediate Path Traversal
- **Recommendation**: Before using file paths from user input, they should be cleaned and validated to ensure they are not malicious. At a minimum, use `filepath.Clean`. For stronger security, ensure the resolved path is within an expected base directory.
- **Code Example (`cmd/trix/main.go`)**:

```go
import "path/filepath"

func handleEncode(cmd *cobra.Command, inputFile, outputFile, ...
    // ...
    // Clean the output path
    safeOutputFile := filepath.Clean(outputFile)
    if outputFile != "" && safeOutputFile != outputFile {
        return fmt.Errorf("invalid output path")
    }
    // Use safeOutputFile for writing
    return ioutil.WriteFile(safeOutputFile, encoded, 0644)
}
```
*(Apply similar logic to all file handling functions)*

### d. Remediate Leaky Error Messages
- **Recommendation**: Make error messages less specific to external users.
- **Code Example (`pkg/trix/trix.go`)**:

```go
// In trix.Decode function
if string(magic) != magicNumber {
    // OLD: return nil, fmt.Errorf("%w: expected %s, got %s", ErrInvalidMagicNumber, magicNumber, string(magic))
    // NEW:
    return nil, ErrInvalidMagicNumber
}
```
