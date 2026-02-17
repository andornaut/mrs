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
- **Concurrency:** `mrs` uses file-based locking (`<name>.lock`) to prevent multiple processes from corrupting a vault simultaneously. Exclusive locks are used for writes, and shared locks for reads.
- **Backups:** Every `Write` operation automatically creates a `<name>.<salt>.bak` file of the previous version.
- **Auto-migration:** Decryption supports legacy KDF iterations (4,096) and will automatically upgrade to 600,000 iterations on the next save.

### Secrets
A secret is a newline-delimited paragraph within a vault.
- The first line is the **key** (used for searching).
- Subsequent lines are the **value**.
- Secrets are separated by one or more blank lines.

## Repository Structure

- `main.go`: Application entry point. Handles signal-safe cleanup of temporary files.
- `cmd/`: CLI command definitions (using Cobra). 
  - Uses option structs for flag management to isolate state.
  - `cmd.go`: Root command and core subcommands (`add`, `edit`, `search`).
  - `vaultcmd/`: Subcommands for vault management (`create`, `delete`, `list`, etc.).
- `internal/`: Private application code.
  - `config/`: Configuration handling (environment variables). Functions return errors instead of using global state or exiting.
  - `crypto/`: Encryption, decryption, and secure memory handling (wiping).
  - `fs/`: Filesystem utilities (includes `CopyFile` for backups).
  - `prompt/`: Interactive CLI prompts (uses `golang.org/x/term` for passwords).
  - `secret/`: Logic for manipulating secrets within an unlocked vault.
  - `vault/`: Vault management logic (finding, creating, unlocking, locking, backup/migration).

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
- **GitHub Actions (`test.yml`)**: Automatically runs tests and `golangci-lint` (v2) on every push and PR to the `main` branch across Linux and macOS. Uses `golangci-lint-action`.
- **Release Automation (`release.yml`)**: Uses **GoReleaser** to build and publish binaries when a `v*` tag is pushed.

## Tips for Agents

- **Memory Security:** Sensitive data (passwords, plaintext secrets, keys) should be handled as `[]byte` and explicitly zeroed out using `crypto.Wipe()` as soon as they are no longer needed.
- **Vault State:** Use `UnlockedVault.Wipe()` to clear sensitive data from an unlocked vault instance. Use `UnlockedVault.IsBad()` to check for validity.
- **Locking:** Always acquire the appropriate lock (`ExclusiveLock` or `SharedLock`) before performing operations on a vault file.
- **Error Handling:** All `internal` packages should return errors to the caller. Avoid `log.Fatal` or `os.Exit` inside libraries.
- **Temporary Files:** `mrs` creates a temporary directory for decrypted files during editing. This is cleaned up by `main.go` using a signal-aware cleanup routine.
- **Modern Go:** Avoid `io/ioutil`. Use `os` or `io` instead.
- **Term handling:** Use `golang.org/x/term` for terminal-related operations.
