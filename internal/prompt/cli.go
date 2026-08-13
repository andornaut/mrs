package prompt

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/andornaut/mrs/internal/crypto"
)

func PromptName() (string, error) {
	name, err := TrimmedLine("Vault name")
	if err != nil {
		return "", err
	}
	if name == "" {
		// Reached by a user who answered the prompt with a bare newline, and
		// by any caller with nothing on stdin to answer it. Neither learns
		// anything from being told a name cannot be empty.
		return "", errors.New("no vault name given. Use --vault to name one")
	}
	return name, nil
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
		return nil, withFlagHint(err, "--password-file")
	}
	return p, nil
}

// GivenOrPromptConfirmedPassword returns the password for a vault being
// created, from a file or from two prompts that must agree.
func GivenOrPromptConfirmedPassword(passwordFile string) ([]byte, error) {
	return givenOrPromptConfirmed(passwordFile, "Vault password", "--password-file")
}

// GivenOrPromptNewPassword returns the password a vault is being changed to,
// from a file or from two prompts that must agree.
func GivenOrPromptNewPassword(newPasswordFile string) ([]byte, error) {
	return givenOrPromptConfirmed(newPasswordFile, "New password", "--new-password-file")
}

func givenOrPromptConfirmed(passwordFile, msg, flag string) ([]byte, error) {
	if passwordFile != "" {
		return readPasswordFile(passwordFile)
	}
	p, err := Password(msg)
	if err != nil {
		return nil, withFlagHint(err, flag)
	}
	c, err := Password("Confirm password")
	if err != nil {
		crypto.Wipe(p)
		return nil, withFlagHint(err, flag)
	}
	defer crypto.Wipe(c)

	if !crypto.SecureCompare(p, c) {
		crypto.Wipe(p)
		return nil, errors.New("password mismatch")
	}
	return p, nil
}

// withFlagHint names the flag that supplies a password without a terminal. The
// prompt itself cannot name it, because which flag applies depends on which
// password is being asked for: --password-file supplies a vault's current
// password and cannot supply the one it is being changed to.
func withFlagHint(err error, flag string) error {
	if errors.Is(err, ErrNoTerminal) {
		return fmt.Errorf("%w. Use %s to supply the password", err, flag)
	}
	return err
}

func readPasswordFile(passwordFile string) ([]byte, error) {
	password, err := os.ReadFile(passwordFile)
	if err != nil {
		return nil, fmt.Errorf("could not read from password file %q: %w", passwordFile, err)
	}
	// Trim trailing newlines, which editors and `echo` append, to match what
	// the interactive password prompt returns.
	return bytes.TrimRight(password, "\r\n"), nil
}
