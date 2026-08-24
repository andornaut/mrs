package secret

import (
	"bytes"
	"fmt"
	"os"

	"github.com/andornaut/mrs/internal/crypto"
	"github.com/andornaut/mrs/internal/fs"
	"github.com/andornaut/mrs/internal/prompt"
	"github.com/andornaut/mrs/internal/vault"
)

func readSecrets(v vault.UnlockedVault) (*secretList, error) {
	plaintext, err := v.Decrypt()
	if err != nil {
		return nil, err
	}
	// parseSecrets copies what it keeps, so the vault's own plaintext is wiped
	// here rather than left for the secretList's owner to remember.
	defer crypto.Wipe(plaintext)
	return parseSecrets(plaintext)
}

func editSecrets(content []byte) (*secretList, error) {
	p, err := fs.WriteTempFile(content)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = os.Remove(p)
	}()

	if err = prompt.Editor(p); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		// Say that the file being read back is the one the editor was given. An
		// editor is expected to save over that file, so a read that fails here
		// is one that moved or removed it instead, and the bare error names a
		// temporary path the user has never seen.
		return nil, fmt.Errorf("could not read back the file the editor was given: %w", err)
	}
	defer crypto.Wipe(b)
	return parseSecrets(b)
}

// maxLineLen bounds the length of a single line of secrets. A value is often a
// single long line - a certificate or a token pasted without line breaks - so
// the limit is generous; what it guards against is a file that is not secrets
// at all being read into memory a line at a time.
const maxLineLen = 16 * 1024 * 1024

// parseSecrets parses plaintext into secrets, copying what it keeps so that the
// caller can wipe what it was given. The secretList owns its copies, and its
// Wipe method is what clears them.
func parseSecrets(plaintext []byte) (*secretList, error) {
	var (
		entry   []byte
		secrets []secret
	)
	for rest := plaintext; len(rest) > 0; {
		var line []byte
		if before, after, ok := bytes.Cut(rest, []byte{'\n'}); ok {
			line, rest = before, after
		} else {
			line, rest = rest, nil
		}
		// A line scanner drops the carriage return of a CRLF, and a vault
		// edited on Windows has to round-trip like any other.
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) > maxLineLen {
			return nil, fmt.Errorf("a line of secrets is longer than the %d MiB limit", maxLineLen/(1024*1024))
		}
		// A line is stored as it was typed. Only the test for a blank line -
		// the separator between secrets - ignores whitespace, so that a value
		// that is indented, or that ends in a space, survives a round trip.
		if len(bytes.TrimSpace(line)) == 0 {
			if len(entry) > 0 {
				secrets = append(secrets, secret(entry))
				entry = nil
			}
			continue
		}
		entry = append(entry, line...)
		// The line terminator is stripped above, so re-add one here.
		entry = append(entry, '\n')
	}
	if len(entry) > 0 {
		// Entries are appended when a blank line is reached, so handle the case
		// where there are none.
		secrets = append(secrets, secret(entry))
	}
	return newSecretList(secrets), nil
}
