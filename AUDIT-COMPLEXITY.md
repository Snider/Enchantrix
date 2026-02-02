# Code Complexity and Maintainability Audit

This document outlines the findings of a code complexity and maintainability audit of the Enchantrix project.

## Methodology

The audit was conducted by analyzing the Go source code for the following:

*   **Cyclomatic Complexity:** Functions with high complexity.
*   **Cognitive Complexity:** Code that is difficult to understand.
*   **Code Duplication:** Violations of the DRY (Don't Repeat Yourself) principle.
*   **Maintainability Issues:** Long methods, large classes, deep nesting, long parameter lists, dead code, and commented-out code.
*   **Code Smells:** Common indicators of deeper design problems.

## Findings

The findings are prioritized by their potential impact on the maintenance burden.

---

## 1. Code Duplication in `cmd/trix/main.go`

**Finding:** The functions `handleEncode`, `handleDecode`, `handleHash`, and `handleSigil` contain duplicated code for reading input from either a file or stdin. This violates the Don't Repeat Yourself (DRY) principle and makes the code harder to maintain.

**Example of Duplicated Code:**

```go
// From handleEncode
var data []byte
var err error
if inputFile == "" || inputFile == "-" {
    data, err = ioutil.ReadAll(cmd.InOrStdin())
} else {
    data, err = ioutil.ReadFile(inputFile)
}
if err != nil {
    return err
}

// From handleDecode
var data []byte
var err error
if inputFile == "" || inputFile == "-" {
    data, err = ioutil.ReadAll(cmd.InOrStdin())
} else {
    data, err = ioutil.ReadFile(inputFile)
}
if err != nil {
    return err
}
```

**Recommendation:** Abstract the input reading logic into a single helper function.

**Refactoring Approach:** Create a new function, `readInput`, that centralizes the logic for reading from a file or stdin.

**Proposed `readInput` function:**

```go
func readInput(cmd *cobra.Command, inputFile string) ([]byte, error) {
    if inputFile == "" || inputFile == "-" {
        return ioutil.ReadAll(cmd.InOrStdin())
    }
    return ioutil.ReadFile(inputFile)
}
```

**Refactored `handleEncode` function:**

```go
func handleEncode(cmd *cobra.Command, inputFile, outputFile, magicNumber string, sigils []string) error {
    if len(magicNumber) != 4 {
        return fmt.Errorf("magic number must be 4 bytes long")
    }
    data, err := readInput(cmd, inputFile)
    if err != nil {
        return err
    }

    t := &trix.Trix{
        Header:   make(map[string]interface{}),
        Payload:  data,
        InSigils: sigils,
    }

    if err := t.Pack(); err != nil {
        return err
    }

    encoded, err := trix.Encode(t, magicNumber, nil)
    if err != nil {
        return err
    }

    if outputFile == "" || outputFile == "-" {
        _, err = cmd.OutOrStdout().Write(encoded)
        return err
    }
    return ioutil.WriteFile(outputFile, encoded, 0644)
}
```

## 2. Long Methods in `pkg/trix/trix.go`

**Finding:** The `Encode` and `Decode` functions in `pkg/trix/trix.go` are both long methods that handle multiple responsibilities. This increases their cognitive complexity and makes them harder to test and maintain.

**`Encode` function responsibilities:**
*   Validating the magic number.
*   Calculating and adding a checksum.
*   Serializing the header to JSON.
*   Writing the magic number, version, header length, header, and payload to a writer.

**`Decode` function responsibilities:**
*   Validating the magic number.
*   Reading and verifying the magic number and version.
*   Reading and validating the header length.
*   Deserializing the header from JSON.
*   Reading the payload.
*   Verifying the checksum.

**Recommendation:** Decompose these methods into smaller, private helper functions, each with a single responsibility.

**Refactoring Approach (`Encode`):**

Create helper functions for handling the checksum and writing the components of the `.trix` file.

**Proposed Helper Functions for `Encode`:**
```go
func (t *Trix) addChecksum() {
    if t.ChecksumAlgo != "" {
        checksum := crypt.NewService().Hash(t.ChecksumAlgo, string(t.Payload))
        t.Header["checksum"] = checksum
        t.Header["checksum_algo"] = string(t.ChecksumAlgo)
    }
}

func writeTrixComponents(w io.Writer, magicNumber string, headerBytes, payload []byte) error {
    if _, err := io.WriteString(w, magicNumber); err != nil {
        return err
    }
    if _, err := w.Write([]byte{byte(Version)}); err != nil {
        return err
    }
    if err := binary.Write(w, binary.BigEndian, uint32(len(headerBytes))); err != nil {
        return err
    }
    if _, err := w.Write(headerBytes); err != nil {
        return err
    }
    if _, err := w.Write(payload); err != nil {
        return err
    }
    return nil
}
```

**Refactored `Encode` function:**
```go
func Encode(trix *Trix, magicNumber string, w io.Writer) ([]byte, error) {
    if len(magicNumber) != 4 {
        return nil, ErrMagicNumberLength
    }

    trix.addChecksum()

    headerBytes, err := json.Marshal(trix.Header)
    if err != nil {
        return nil, err
    }

    var buf *bytes.Buffer
    writer := w
    if writer == nil {
        buf = new(bytes.Buffer)
        writer = buf
    }

    if err := writeTrixComponents(writer, magicNumber, headerBytes, trix.Payload); err != nil {
        return nil, err
    }

    if buf != nil {
        return buf.Bytes(), nil
    }
    return nil, nil
}
```

## 3. Cognitive Complexity in `pkg/crypt/crypt.go`

**Finding:** The `Hash` function in `pkg/crypt/crypt.go` uses a `switch` statement to select the hashing algorithm. While this works for a small number of algorithms, it has a few drawbacks:
*   **High Maintenance:** Adding a new hashing algorithm requires modifying this function.
*   **Increased Complexity:** As more algorithms are added, the `switch` statement will grow, increasing the function's cognitive complexity.
*   **Open/Closed Principle Violation:** The function is not closed for modification.

**`Hash` function `switch` statement:**
```go
func (s *Service) Hash(lib HashType, payload string) string {
    switch lib {
    case LTHN:
        return lthn.Hash(payload)
    case SHA512:
        hash := sha512.Sum512([]byte(payload))
        return hex.EncodeToString(hash[:])
    case SHA1:
        hash := sha1.Sum([]byte(payload))
        return hex.EncodeToString(hash[:])
    case MD5:
        hash := md5.Sum([]byte(payload))
        return hex.EncodeToString(hash[:])
    case SHA256:
        fallthrough
    default:
        hash := sha256.Sum256([]byte(payload))
        return hex.EncodeToString(hash[:])
    }
}
```

**Recommendation:** Apply the Strategy design pattern by using a map to store the hashing functions. This will make the `Hash` function more extensible and easier to maintain.

**Refactoring Approach:**

1.  Create a type for the hashing functions.
2.  Create a map to store the hashing functions, keyed by the `HashType`.
3.  In the `NewService` function, initialize the map with the available hashing algorithms.
4.  In the `Hash` function, look up the hashing function in the map and execute it.

**Proposed Refactoring:**

```go
// In the Service struct
type hashFunc func(string) string

type Service struct {
    rsa        *rsa.Service
    pgp        *pgp.Service
    hashAlgos map[HashType]hashFunc
}

// In the NewService function
func NewService() *Service {
    s := &Service{
        rsa: rsa.NewService(),
        pgp: pgp.NewService(),
    }
    s.hashAlgos = map[HashType]hashFunc{
        LTHN:   lthn.Hash,
        SHA512: func(p string) string { h := sha512.Sum512([]byte(p)); return hex.EncodeToString(h[:]) },
        SHA256: func(p string) string { h := sha256.Sum256([]byte(p)); return hex.EncodeToString(h[:]) },
        SHA1:   func(p string) string { h := sha1.Sum([]byte(p)); return hex.EncodeToString(h[:]) },
        MD5:    func(p string) string { h := md5.Sum([]byte(p)); return hex.EncodeToString(h[:]) },
    }
    return s
}

// Refactored Hash function
func (s *Service) Hash(lib HashType, payload string) string {
    if f, ok := s.hashAlgos[lib]; ok {
        return f(payload)
    }
    // Default to SHA256 if the algorithm is not found
    return s.hashAlgos[SHA256](payload)
}
```

## 4. Encapsulation Issues in `pkg/crypt/std/lthn/lthn.go`

**Finding:** The `lthn` package uses a global `keyMap` variable for character substitutions. This variable can be modified at runtime using the `SetKeyMap` function, creating a package-level state that is shared across all callers. This design has several drawbacks:

*   **Concurrency Unsafe:** If multiple goroutines use the `lthn` package concurrently, a call to `SetKeyMap` in one goroutine will affect the hashing results in all others, leading to race conditions and unpredictable behavior.
*   **Difficult to Test:** Tests that need to modify the `keyMap` must use mutexes and cleanup functions to avoid interfering with other tests running in parallel.
*   **Poor Encapsulation:** The hashing logic is not self-contained. Its behavior depends on a hidden, global dependency (`keyMap`), which makes the code harder to reason about.

**Code Exhibiting the Issue:**

```go
var keyMap = map[rune]rune{
    // ... default mappings
}

func SetKeyMap(newKeyMap map[rune]rune) {
    keyMap = newKeyMap
}

func Hash(input string) string {
    salt := createSalt(input) // Uses the global keyMap
    hash := sha256.Sum256([]byte(input + salt))
    return hex.EncodeToString(hash[:])
}
```

**Recommendation:** Refactor the package to be stateless by encapsulating the `keyMap` within a struct. This will make the package safe for concurrent use and easier to test.

**Refactoring Approach:**

1.  Create a `Lethn` struct to hold the `keyMap`.
2.  Create a `New` function to initialize the `Lethn` struct with a default or custom `keyMap`.
3.  Change the `Hash`, `Verify`, and `createSalt` functions into methods on the `Lethn` struct.
4.  Provide a package-level `Hash` function that uses a default `Lethn` instance for backward compatibility.

**Proposed Refactoring:**

```go
package lthn

import (
    "crypto/sha256"
    "encoding/hex"
)

// Lethn holds the configuration for the LTHN hashing algorithm.
type Lethn struct {
    keyMap map[rune]rune
}

// New creates a new Lethn instance with the provided keyMap.
// If no keyMap is provided, the default keyMap is used.
func New(keyMap ...map[rune]rune) *Lethn {
    l := &Lethn{
        keyMap: defaultKeyMap,
    }
    if len(keyMap) > 0 {
        l.keyMap = keyMap[0]
    }
    return l
}

var defaultKeyMap = map[rune]rune{
    'o': '0', 'l': '1', 'e': '3', 'a': '4', 's': 'z', 't': '7',
    '0': 'o', '1': 'l', '3': 'e', '4', 'a', '7': 't',
}

// Hash computes the LTHN hash of the input string.
func (l *Lethn) Hash(input string) string {
    salt := l.createSalt(input)
    hash := sha256.Sum256([]byte(input + salt))
    return hex.EncodeToString(hash[:])
}

// createSalt derives a quasi-salt from the input string.
func (l *Lethn) createSalt(input string) string {
    if input == "" {
        return ""
    }
    runes := []rune(input)
    salt := make([]rune, len(runes))
    for i := 0; i < len(runes); i++ {
        char := runes[len(runes)-1-i]
        if replacement, ok := l.keyMap[char]; ok {
            salt[i] = replacement
        } else {
            salt[i] = char
        }
    }
    return string(salt)
}

// Verify checks if an input string produces the given hash.
func (l *Lethn) Verify(input string, hash string) bool {
    return l.Hash(input) == hash
}

// Default instance for backward compatibility
var defaultLethn = New()

// Hash is a package-level function that uses the default Lethn instance.
func Hash(input string) string {
    return defaultLethn.Hash(input)
}

// Verify is a package-level function that uses the default Lethn instance.
func Verify(input string, hash string) bool {
    return defaultLethn.Verify(input, hash)
}
```
