package prompt

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/andornaut/mrs/internal/crypto"
)

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
// created, from a file or from two prompts that must agree. validate refuses a
// password the caller will not accept.
func GivenOrPromptConfirmedPassword(validate func([]byte) error, passwordFile string) ([]byte, error) {
	return givenOrPromptConfirmed(validate, passwordFile, "Vault password", "--password-file")
}

// GivenOrPromptNewPassword returns the password a vault is being changed to,
// from a file or from two prompts that must agree. validate refuses a password
// the caller will not accept.
func GivenOrPromptNewPassword(validate func([]byte) error, newPasswordFile string) ([]byte, error) {
	return givenOrPromptConfirmed(validate, newPasswordFile, "New password", "--new-password-file")
}

// givenOrPromptConfirmed takes validate rather than calling into the vault
// package, which would make prompt depend on it to ask a question.
//
// A typed password is checked before it is asked for a second time: a password
// mrs will not accept is refused after one entry rather than after two. A
// password read from a file is checked as soon as it is read, before anything
// else is asked for. The caller checks again, which is the answer that counts.
func givenOrPromptConfirmed(validate func([]byte) error, passwordFile, msg, flag string) ([]byte, error) {
	if passwordFile != "" {
		p, err := readPasswordFile(passwordFile)
		if err != nil {
			return nil, err
		}
		if validateErr := validate(p); validateErr != nil {
			crypto.Wipe(p)
			return nil, validateErr
		}
		return p, nil
	}
	p, err := Password(msg)
	if err != nil {
		return nil, withFlagHint(err, flag)
	}
	if validateErr := validate(p); validateErr != nil {
		crypto.Wipe(p)
		return nil, validateErr
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
