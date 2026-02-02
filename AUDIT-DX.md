# Developer Experience (DX) Audit

## Onboarding

### Time to First Build
- How long?

The first build is very fast.

```bash
time go build -o trix cmd/trix/main.go
```

Output:
```
real	0m0.242s
user	0m0.408s
sys	0m0.203s
```

### Dependencies
- Easy to install?

Go module dependencies are automatically handled by the `go` command (e.g., `go build`), which is standard and easy for Go developers.

The project has a couple of external dependencies for development:
- `mkdocs` and `mkdocs-material` for documentation, installed via `pip`.
- `task` for running scripts in `Taskfile.yml`.

The `README.md` clearly states the `mkdocs` dependency. The `task` dependency is implied by the presence of `Taskfile.yml`. Adding an "Installation" or "Setup" section to the `README.md` to list all development dependencies would be a small improvement.

### Documentation
- Clear enough?

The documentation is excellent.
- The `README.md` provides a great starting point with clear installation instructions, quick start examples, and an overview of the project structure.
- The `docs` directory contains a well-organized MkDocs site with more in-depth documentation.
- The `CLAUDE.md` file is a fantastic and forward-thinking addition for AI-assisted development.
- The `rfcs` directory provides valuable insight into the design decisions of the project.

### Gotchas
- Undocumented issues?

1.  **`task` dependency:** The use of `task` is not explicitly mentioned in the `README.md`. A new developer might need to install it (`npm install -g @go-task/cli`).
2.  **Go 1.25 `covdata` issue:** When running tests with Go 1.25, an error `go: no such tool "covdata"` can occur. This requires a one-time fix: `go env -w GOTOOLCHAIN=go1.25.0+auto`. This should be documented.

## Development Workflow

### Local Development
- Hot reload?
  - Not applicable for this CLI tool.
- Fast feedback loop?
  - Yes. The fast build and test times provide a quick feedback loop.
- Easy debugging?
  - Yes. Standard Go debugging tools (e.g., Delve) can be used. No special configuration is needed.

### Testing
- Fast test runs?
  - Yes, the entire test suite runs in under 4 seconds.
  ```
  real	0m3.883s
  user	0m8.490s
  sys	0m4.064s
  ```
- Easy to run single test?
  - Yes, the `CLAUDE.md` file provides clear instructions for running single tests using the standard `go test -run` command.
- Good test output?
  - Yes, the `task test` command provides verbose output, including test names, status, and a final coverage percentage. The output is easy to read and understand.

### Build System
- Intuitive commands?
  - Yes, the `Taskfile.yml` provides a clear and intuitive set of commands (`test`, `build`, `fmt`, `vet`). The standard `go` commands also work as expected.
- Clear error messages?
  - Yes, the build system's error messages (from `go build`, `go test`, etc.) are standard and clear to Go developers.
- Incremental builds?
  - Yes, Go's build system provides incremental builds by default.

### Tooling
- IDE Support - Editor configs?
  - There are no editor-specific configurations (e.g., `.vscode/`, `.editorconfig`) in the repository. Adding an `.editorconfig` file would be a good practice to ensure consistent formatting across different editors.
- Linting - Auto-fixable?
  - The `task vet` command runs `go vet`, which is a standard linter for Go. It does not provide auto-fixing. More advanced linters like `golangci-lint` could be added for more comprehensive checks and auto-fixing capabilities.
- Formatting - Pre-commit hooks?
  - The `task fmt` command runs `go fmt`. There are no pre-commit hooks configured to automatically format code before committing. This would be a valuable addition to maintain a consistent code style.
- Type Checking - Type hints?
  - Go is a statically typed language, so type checking is a core feature.

## CLI/Interface

### Help Text
- Useful --help?

The `--help` output is clear and well-structured, thanks to the Cobra library.

```
trix is a command-line tool for working with the .trix file format, which is used for storing encrypted data.

Usage:
  trix [command]

Available Commands:
  base64      Apply the base64 sigil
  blake2b-256 Apply the blake2b-256 sigil
  blake2b-384 Apply the blake2b-384 sigil
  blake2b-512 Apply the blake2b-512 sigil
  blake2s-256 Apply the blake2s-256 sigil
  completion  Generate the autocompletion script for the specified shell
  decode      Decode a .trix file
  encode      Encode a file to the .trix format
  gzip        Apply the gzip sigil
  hash        Hash a file using a specified algorithm
  help        Help about any command
  hex         Apply the hex sigil
  json        Apply the json sigil
  json-indent Apply the json-indent sigil
  md4         Apply the md4 sigil
  md5         Apply the md5 sigil
  reverse     Apply the reverse sigil
  ripemd160   Apply the ripemd160 sigil
  sha1        Apply the sha1 sigil
  sha224      Apply the sha224 sigil
  sha256      Apply the sha256 sigil
  sha3-224    Apply the sha3-224 sigil
  sha3-256    Apply the sha3-256 sigil
  sha3-384    Apply the sha3-384 sigil
  sha3-512    Apply the sha3-512 sigil
  sha384      Apply the sha384 sigil
  sha512      Apply the sha512 sigil
  sha512-224  Apply the sha512-224 sigil
  sha512-256  Apply the sha512-256 sigil

Flags:
  -h, --help   help for trix

Use "trix [command] --help" for more information about a command.
```

The large number of sigil commands in the root help output could be overwhelming. Grouping the sigil commands under a single `sigil` subcommand (e.g., `trix sigil base64`) might improve the user experience.

The help text for the `encode` subcommand is clear, but it's missing information about how to apply sigils.

```
Encode a file to the .trix format

Usage:
  trix encode [flags]

Flags:
  -h, --help            help for encode
  -i, --input string    Input file (or stdin)
  -m, --magic string    Magic number (4 bytes)
  -o, --output string   Output file
```

The `README.md` shows that sigils are passed as positional arguments (e.g., `trix encode --output message.trix --magic TRIX base64`), but this is not mentioned in the help text. Adding a `[sigils...]` to the `Usage` string would make this clearer.

Similarly, the `decode` subcommand is also missing the `[sigils...]` positional argument in its usage string.

```
Decode a .trix file

Usage:
  trix decode [flags]

Flags:
  -h, --help            help for decode
  -i, --input string    Input file (or stdin)
  -m, --magic string    Magic number (4 bytes)
  -o, --output string   Output file
```

### Error Messages
- Actionable?

Yes, the error messages are actionable and provide good feedback to the user. For example, providing an invalid hash algorithm to the `hash` command produces the following output:

```
Error: invalid hash algorithm: invalid-algorithm
Usage:
  trix hash [algorithm] [flags]

Flags:
  -h, --help           help for hash
  -i, --input string   Input file (or stdin)
```

This is a good error message because it:
1. Clearly states what is wrong ("invalid hash algorithm").
2. Shows the invalid value that was provided ("invalid-algorithm").
3. Prints the usage information for the command, which helps the user correct the input.

### Progress Feedback
- Long operations?

  - The tool is designed for local data transformation and is very fast. There are no long-running operations that would require progress feedback.

### Configuration
- Sensible defaults?

  - The CLI has sensible defaults. For example, the `input` and `output` flags default to stdin and stdout, respectively, which is a common and useful convention for CLI tools.

## Pain Points
- **Undocumented Dependencies:** The `task` dependency and the `GOTOOLCHAIN` fix for Go 1.25 are not documented, which could cause minor frustration for new contributors.
- **CLI Usability:** The large number of sigil commands in the root help output can be overwhelming, and the `encode`/`decode` help texts are missing information about sigils.
- **Lack of Automated Tooling:** The absence of pre-commit hooks for formatting and more advanced linting means that maintaining code quality relies more on manual developer effort.

## Suggestions for Improvement

1.  **Documentation:**
    -   Add a "Development" or "Contributing" section to the `README.md` that explicitly lists all development dependencies (`task`, `mkdocs`).
    -   Add a note about the `GOTOOLCHAIN` fix for Go 1.25 to the "Development" section.

2.  **CLI:**
    -   Consider grouping the sigil commands under a single `sigil` subcommand (e.g., `trix sigil base64`) to declutter the root command's help output.
    -   Add `[sigils...]` to the `Usage` string for the `encode` and `decode` subcommands to make it clear that they accept sigils as positional arguments.

3.  **Tooling:**
    -   Add an `.editorconfig` file to ensure consistent formatting across different editors.
    -   Add a pre-commit hook (e.g., using Husky or a similar tool) to automatically run `go fmt` before each commit.
    -   Consider adding a more advanced linter like `golangci-lint` to the `Taskfile.yml` and the pre-commit hooks to catch a wider range of issues automatically.
