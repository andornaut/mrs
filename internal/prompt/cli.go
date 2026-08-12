package prompt

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/andornaut/mrs/internal/crypto"
)

func PromptName() (string, error) {
	return TrimmedLine("Vault name")
}

func GivenOrPromptName(namePrefix string) (string, error) {
	if namePrefix == "" {
		return PromptName()
	}
	return namePrefix, nil
}

func GivenOrPromptPassword(passwordFile string) ([]byte, error) {
	if passwordFile != "" {
		return readPasswordFile(passwordFile)
	}
	p, err := Password("Vault password")
	if err != nil {
		return nil, withPasswordFileHint(err)
	}
	return p, nil
}

func GivenOrPromptConfirmedPassword(passwordFile string) ([]byte, error) {
	if passwordFile != "" {
		return readPasswordFile(passwordFile)
	}
	p, err := Password("Vault password")
	if err != nil {
		return nil, withPasswordFileHint(err)
	}
	c, err := Password("Confirm password")
	if err != nil {
		crypto.Wipe(p)
		return nil, withPasswordFileHint(err)
	}
	defer crypto.Wipe(c)

	if !crypto.SecureCompare(p, c) {
		crypto.Wipe(p)
		return nil, errors.New("password mismatch")
	}
	return p, nil
}

// withPasswordFileHint names the flag that supplies a password without a
// terminal, for the prompts that flag can stand in for. The prompt itself
// cannot say this: --password-file supplies only the vault's current password,
// so it is no help to `vault change-password` asking for the new one.
func withPasswordFileHint(err error) error {
	if errors.Is(err, ErrNoTerminal) {
		return fmt.Errorf("%w. use --password-file to supply the password", err)
	}
	return err
}

func readPasswordFile(passwordFile string) ([]byte, error) {
	password, err := os.ReadFile(passwordFile)
	if err != nil {
		return nil, fmt.Errorf("could not read from password file %s: %s", passwordFile, err)
	}
	// Trim trailing newlines, which editors and `echo` append, to match what
	// the interactive password prompt returns.
	return bytes.TrimRight(password, "\r\n"), nil
}
