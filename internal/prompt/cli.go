package prompt

import (
	"errors"
	"fmt"
	"os"
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

func GivenOrPromptPassword(passwordFile string) (string, error) {
	if passwordFile != "" {
		return readPasswordFile(passwordFile)
	}
	return Password("Vault password")
}

func GivenOrPromptConfirmedPassword(passwordFile string) (string, error) {
	if passwordFile != "" {
		return readPasswordFile(passwordFile)
	}
	p, err := Password("Vault password")
	if err != nil {
		return "", err
	}
	c, err := Password("Confirm password")
	if err != nil {
		return "", err
	}
	if p != c {
		return "", errors.New("password mismatch")
	}
	return p, nil
}

func readPasswordFile(passwordFile string) (string, error) {
	password, err := os.ReadFile(passwordFile)
	if err != nil {
		return "", fmt.Errorf("could not read from password file %s: %s", passwordFile, err)
	}
	return string(password), nil
}
