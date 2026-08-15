package secret

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/andornaut/mrs/internal/config"
	"github.com/andornaut/mrs/internal/crypto"
	"github.com/andornaut/mrs/internal/fs"
	"github.com/andornaut/mrs/internal/prompt"
	"github.com/andornaut/mrs/internal/vault"
)

// instructionLines are shown at the top of an editor session. They are removed
// when the session is saved, by matching them exactly, so that every other
// line - including a line that begins with a "#" - is kept as the user typed it.
var instructionLines = []string{
	"# Secrets are separated by blank lines.",
	"# The first line of each secret is its unique key.",
	"# These three lines are removed when you save; every other line is kept.",
}

// The extra newline at the end is intended to create an inviting starting point for editing.
var instructions = strings.Join(instructionLines, "\n") + "\n\n"

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
	showInstructions := !config.HideEditorInstructions()
	if showInstructions {
		buf := make([]byte, 0, len(instructions)+len(content))
		buf = append(buf, instructions...)
		buf = append(buf, content...)
		defer crypto.Wipe(buf)
		content = buf
	}
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
		return nil, err
	}
	defer crypto.Wipe(b)
	if showInstructions {
		// A copy of everything the editor was given, minus the instructions, so
		// it is wiped alongside the original rather than left behind by it.
		stripped := stripInstructions(b)
		defer crypto.Wipe(stripped)
		return parseSecrets(stripped)
	}
	return parseSecrets(b)
}

// stripInstructions removes the instructions that mrs prepended to an editor
// session, wherever they ended up. An editor opens with the cursor on the first
// line, so a user who starts typing pushes them down the buffer, and removing
// only a leading block would encrypt them as part of a secret. Only those exact
// lines are removed, so a line of the user's own that begins with a "#" is kept
// as a secret rather than silently discarded.
func stripInstructions(b []byte) []byte {
	var kept [][]byte
	for line := range bytes.SplitSeq(b, []byte("\n")) {
		// Compared as bytes: converting each line to a string to trim it would
		// make an unwipeable copy of every line of the editor's buffer.
		trimmed := bytes.TrimSpace(line)
		if isInstruction(trimmed) {
			continue
		}
		// A blank line before anything else is the gap mrs left below the
		// instructions, so it goes with them.
		if len(kept) == 0 && len(trimmed) == 0 {
			continue
		}
		kept = append(kept, line)
	}
	return bytes.Join(kept, []byte("\n"))
}

func isInstruction(line []byte) bool {
	return slices.ContainsFunc(instructionLines, func(l string) bool {
		return bytes.Equal(line, []byte(l))
	})
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
