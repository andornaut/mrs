package secret

import (
	"bufio"
	"io"
	"os"
	"strings"

	"github.com/andornaut/mrs/internal/config"
	"github.com/andornaut/mrs/internal/fs"
	"github.com/andornaut/mrs/internal/prompt"
	"github.com/andornaut/mrs/internal/vault"
)

// The extra newline at the end is intended to create an inviting starting point for editing.
const instructions = "# Secrets are separated by blank lines.\n" +
	"# The first line of each secret is its unique key.\n" +
	"# Lines that begin with a # character are ignored.\n\n"

func retrieveBriefcase(v vault.UnlockedVault) (*briefcase, error) {
	r, err := v.NewReader()
	if err != nil {
		return nil, err
	}
	return transcribe(r)
}

func takeDictation(content string) (*briefcase, error) {
	if !config.HideEditorInstructions() {
		content = instructions + content
	}
	p, err := fs.WriteTempFile(content)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = fs.RemoveFile(p)
	}()

	if err := prompt.Editor(p); err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return transcribe(f)
}

func transcribe(r io.Reader) (*briefcase, error) {
	var (
		entry   string
		secrets []secret
	)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if line == "" {
			if entry != "" {
				secrets = append(secrets, secret(entry))
				entry = ""
			}
			continue
		}
		// Trailing newlines are stripped above, so re-add one here
		entry += line + "\n"
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if entry != "" {
		// Entries are appended when the scanner encounters a blank line, so
		// handle the case where there are none.
		secrets = append(secrets, secret(entry))
	}
	return newBriefcase(secrets), nil
}
