# Agent's Guide to Mr. Secretary (mrs)

Welcome, fellow agent! This guide provides a quick overview of the `mrs` codebase to help you understand its architecture and how to contribute effectively.

## Project Overview

`mrs` (Mr. Secretary) is a command-line secrets manager for Linux and macOS. It allows users to organize secrets into encrypted "vaults".

- **Language:** Go (Targeting Go 1.26+)
- **CLI Framework:** [Cobra](https://github.com/spf13/cobra)
- **Encryption:** 256-bit AES-GCM (implemented in `internal/crypto`)
- **Key Derivation:** PBKDF2-SHA256 with 600,000 iterations (Current) or 4,096 (Legacy).
- **Storage:** Vaults are stored as encrypted files in `${HOME}/.local/share/mrs` (by default).

## Core Concepts

### Vaults
A vault is a single encrypted file. Each vault has a name and a salt. The filename format is `<name>.<salt>`. 
- **Backups:** Every `Write` operation automatically creates a `<name>.<salt>.bak` file of the previous version.
- **Auto-migration:** Decryption supports legacy KDF iterations (4,096) and will automatically upgrade to 600,000 iterations on the next save.

### Secrets
A secret is a newline-delimited paragraph within a vault.
- The first line is the **key** (used for searching).
- Subsequent lines are the **value**.
- Secrets are separated by one or more blank lines.

## Repository Structure

- `main.go`: Application entry point.
- `cmd/`: CLI command definitions (using Cobra).
  - `cmd.go`: Root command and core subcommands (`add`, `edit`, `search`).
  - `vaultcmd/`: Subcommands for vault management (`create`, `delete`, `list`, etc.).
- `internal/`: Private application code.
  - `config/`: Configuration handling (environment variables).
  - `crypto/`: Encryption and decryption logic.
  - `fs/`: Filesystem utilities (includes `CopyFile` for backups).
  - `prompt/`: Interactive CLI prompts (uses `golang.org/x/term` for passwords).
  - `secret/`: Logic for manipulating secrets within an unlocked vault.
  - `vault/`: Vault management logic (finding, creating, unlocking, backup/migration).

## Development Workflow

### Building
Use the provided `Makefile`:
```bash
make build
```

### Testing
Run tests using:
```bash
go test ./...
```
Unit tests are located in `*_test.go` files within their respective packages.

### CI/CD
- **GitHub Actions (`test.yml`)**: Automatically runs tests and `golangci-lint` on every push and PR to the `main` branch across Linux and macOS.
- **Release Automation (`release.yml`)**: Uses **GoReleaser** to build and publish binaries when a `v*` tag is pushed.

## Tips for Agents

- **Encryption during Tests:** When writing tests that involve encryption, you'll need a password. Ensure salts are at least 32 characters long.
- **Temporary Files:** `mrs` creates a temporary directory for decrypted files during editing. This is cleaned up by `main.go` using a `defer` call to `fs.RemoveTempDir()`.
- **Search Logic:** Search is performed on the first line of each secret by default. The `--full` flag enables searching the entire secret content.
- **Modern Go:** Avoid `io/ioutil`. Use `os` or `io` instead.
- **Term handling:** Use `golang.org/x/term` for terminal-related operations.
