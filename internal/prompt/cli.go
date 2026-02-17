package prompt

import (
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
	return Password("Vault password")
}

func GivenOrPromptConfirmedPassword(passwordFile string) ([]byte, error) {
	if passwordFile != "" {
		return readPasswordFile(passwordFile)
	}
	p, err := Password("Vault password")
	if err != nil {
		return nil, err
	}
	c, err := Password("Confirm password")
	if err != nil {
		crypto.Wipe(p)
		return nil, err
	}
	defer crypto.Wipe(c)

	if !crypto.SecureCompare(p, c) {
		crypto.Wipe(p)
		return nil, errors.New("password mismatch")
	}
	return p, nil
}

func readPasswordFile(passwordFile string) ([]byte, error) {
	password, err := os.ReadFile(passwordFile)
	if err != nil {
		return nil, fmt.Errorf("could not read from password file %s: %s", passwordFile, err)
	}
	return password, nil
}
