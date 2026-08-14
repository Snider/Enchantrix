# API Audit: Enchantrix Library and CLI

## 1. Go Library API Audit (`pkg/`)

### 1.1. Overall Design & Consistency

The public Go API across the `crypt`, `enchantrix`, and `trix` packages is well-designed, consistent, and adheres to Go best practices. The separation of concerns is clear, with each package serving a distinct purpose.

- **Naming Conventions**: Public functions and types consistently use `PascalCase` as is idiomatic in Go.
- **Error Handling**: Errors are returned as the last value from functions and are descriptive (e.g., `ErrInvalidMagicNumber`, `ErrChecksumMismatch`).
- **Structs vs. Functions**: The API strikes a good balance between service-based structs (`crypt.Service`) and data-centric structs with methods (`trix.Trix`), alongside package-level functions where appropriate (`trix.Encode`, `trix.Decode`).

### 1.2. Package-Specific Audit

#### `pkg/crypt`

- **Strengths**:
    - The `crypt.Service` acts as a clean facade for all cryptographic operations.
    - Lazy initialization of internal services (`ensureRSA`, `ensurePGP`) is efficient.
    - The API is grouped logically: Hashing, Checksums, RSA, and PGP.
    - Method names are clear and predictable (e.g., `GenerateRSAKeyPair`, `EncryptRSA`).

- **Recommendations**:
    - **Minor**: The `Hash` function accepts a `crypt.HashType`, while `IsHashAlgo` accepts a `string`. While functional, aligning `IsHashAlgo` to also accept a `crypt.HashType` would improve type safety and consistency.

#### `pkg/enchantrix`

- **Strengths**:
    - The `Sigil` interface is a powerful and elegant abstraction for data transformation.
    - The `NewSigil` factory provides a centralized and user-friendly way to create sigil instances.
    - The separation of standard sigils (`sigils.go`) from cryptographic sigils (`crypto_sigil.go`) is logical and improves organization.
    - The pre-obfuscation layer is a thoughtful security feature that is well-documented and implemented.

- **Recommendations**:
    - **Feature**: The package does not provide a public function to list all available sigil names. The CLI currently uses a hardcoded list, which could lead to inconsistencies. Exposing a `ListSigils() []string` function from this package would be beneficial.

#### `pkg/trix`

- **Strengths**:
    - The `.trix` format is clearly defined and implemented. The `Trix` struct serves as a good in-memory representation.
    - The `Encode` and `Decode` functions provide a simple, high-level API for serialization.
    - Integration with the `enchantrix` package via `Pack` and `Unpack` methods is seamless.
    - Constants are used effectively for header keys (e.g., `HeaderKeyEncrypted`), preventing magic strings.

- **Recommendations**:
    - None. The API is robust and well-designed.

## 2. CLI API Audit (`cmd/trix/`)

### 2.1. Overall Design & Consistency

The `trix` CLI is built on `spf13/cobra`, a standard for modern Go CLIs. It follows common Unix conventions, including the use of `stdin`/`stdout` and file-based I/O.

- **Command Structure**: The command hierarchy is logical and easy to navigate (`trix encode`, `trix decode`, `trix hash`).
- **Flags**: Flags are consistent across commands (`--input`, `--output`, `--magic`) and include convenient short aliases (`-i`, `-o`, `-m`).
- **User Interaction**: The tool provides clear error messages and behaves predictably.

### 2.2. Specific Commands Audit

- **`trix encode`/`decode`**:
    - These commands are the core of the tool and function as expected.
    - **Minor Recommendation**: Sigils are passed as positional arguments (e.g., `trix encode base64 gzip`). While this works, a dedicated flag like `--sigils "base64,gzip"` or repeated flags (`--sigil base64 --sigil gzip`) would be more self-documenting and in line with typical `cobra` application design.

- **`trix hash`**:
    - The command is straightforward and works as expected.

- **Direct Sigil Commands** (`trix hex`, `trix base64`, etc.):
    - This is a clever and useful feature that exposes the power of the `enchantrix` library directly from the command line for quick, one-off transformations.

### 2.3. Maintainability

- **Recommendation**: As noted in the `enchantrix` section, the `availableSigils` slice in `cmd/trix/main.go` is hardcoded. This creates a maintenance burden, as any new sigil added to the `enchantrix` package must also be manually added to this list. This could be resolved by having the `enchantrix` package expose a function to list available sigils.

## 3. Conclusion

The Enchantrix project exhibits a high degree of API quality and consistency in both its Go library and its command-line interface. The design is thoughtful, robust, and adheres to idiomatic Go practices. The few recommendations provided are minor and aimed at further improving maintainability and user experience rather than fixing significant flaws.
