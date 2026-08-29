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
// caller can wipe what it was given. Each secret's copy is allocated at its
// exact size: growing a buffer with append would abandon an unwipeable copy of
// the lines already appended on every reallocation. The secretList owns its
// copies, and its Wipe method is what clears them.
func parseSecrets(plaintext []byte) (*secretList, error) {
	var (
		lines   [][]byte // the current secret's lines, aliasing plaintext
		size    int      // its size once each line is terminated by '\n'
		secrets []secret
	)
	flush := func() {
		if size == 0 {
			return
		}
		entry := make([]byte, 0, size)
		for _, line := range lines {
			entry = append(entry, line...)
			// The line terminator is stripped below, so re-add one here.
			entry = append(entry, '\n')
		}
		secrets = append(secrets, secret(entry))
		lines, size = lines[:0], 0
	}
	for line := range bytes.Lines(plaintext) {
		// bytes.Lines keeps the newline, and a vault edited on Windows has to
		// round-trip like any other, so every trailing carriage return goes
		// with it. Every one, not just one: a line re-read after a save is
		// terminated by the newline written in flush, so stripping one at a
		// time would shed another on each save from a value that ends in one.
		line = bytes.TrimRight(line, "\r\n")
		if len(line) > maxLineLen {
			return nil, fmt.Errorf("a line of secrets is longer than the %d MiB limit", maxLineLen/(1024*1024))
		}
		// A line is stored as it was typed. Only the test for a blank line -
		// the separator between secrets - ignores whitespace, so that a value
		// that is indented, or that ends in a space, survives a round trip.
		if len(bytes.TrimSpace(line)) == 0 {
			flush()
			continue
		}
		lines = append(lines, line)
		size += len(line) + 1
	}
	flush()
	return newSecretList(secrets), nil
}
