package secret

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
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

func retrieveBriefcase(v vault.UnlockedVault) (*briefcase, error) {
	r, err := v.NewReader()
	if err != nil {
		return nil, err
	}
	return transcribe(r)
}

func takeDictation(content string) (*briefcase, error) {
	showInstructions := !config.HideEditorInstructions()
	if showInstructions {
		content = instructions + content
	}
	p, err := fs.WriteTempFile(content)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = fs.RemoveFile(p)
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
		b = stripInstructions(b)
	}
	return transcribe(bytes.NewReader(b))
}

// stripInstructions removes the instructions that mrs prepended to an editor
// session. Only those exact lines are removed, so a line of the user's own that
// begins with a "#" is kept as a secret rather than silently discarded.
func stripInstructions(b []byte) []byte {
	for {
		line, rest, hasMore := bytes.Cut(b, []byte("\n"))
		s := strings.TrimSpace(string(line))
		if s != "" && !isInstruction(s) {
			return b
		}
		if !hasMore {
			return nil
		}
		b = rest
	}
}

func isInstruction(line string) bool {
	return slices.Contains(instructionLines, line)
}

// maxLineLen bounds the length of a single line of secrets. A value is often a
// single long line - a certificate or a token pasted without line breaks - and
// bufio.Scanner's 64KiB default rejects the whole vault, which locks the user
// out of add, edit and search on a vault that import and export handle fine.
const maxLineLen = 16 * 1024 * 1024

func transcribe(r io.Reader) (*briefcase, error) {
	var (
		entry   string
		secrets []secret
	)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), maxLineLen)
	for scanner.Scan() {
		// A line is stored as it was typed. Only the test for a blank line -
		// the separator between secrets - ignores whitespace, so that a value
		// that is indented, or that ends in a space, survives a round trip.
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			if entry != "" {
				secrets = append(secrets, secret(entry))
				entry = ""
			}
			continue
		}
		// The line terminator is stripped by the scanner, so re-add one here
		entry += line + "\n"
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("a line of secrets is longer than the %d MiB limit", maxLineLen/(1024*1024))
		}
		return nil, err
	}
	if entry != "" {
		// Entries are appended when the scanner encounters a blank line, so
		// handle the case where there are none.
		secrets = append(secrets, secret(entry))
	}
	return newBriefcase(secrets), nil
}
