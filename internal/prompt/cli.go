package prompt

import (
	"errors"
	"fmt"
	"io/ioutil"
)

func PromptName() string {
	return TrimmedLine("Vault name")
}

func GivenOrPromptName(namePrefix string) string {
	if namePrefix == "" {
		return PromptName()
	}
	return namePrefix
}

func GivenOrPromptPassword(passwordFile string) (string, error) {
	if passwordFile != "" {
		return readPasswordFile(passwordFile)
	}
	return Password("Vault password"), nil
}

func GivenOrPromptConfirmedPassword(passwordFile string) (string, error) {
	if passwordFile != "" {
		return readPasswordFile(passwordFile)
	}
	p := Password("Vault password")
	c := Password("Confirm password")
	if p != c {
		return "", errors.New("Password mismatch")
	}
	return p, nil
}

func readPasswordFile(passwordFile string) (string, error) {
	password, err := ioutil.ReadFile(passwordFile)
	if err != nil {
		return "", fmt.Errorf("Could not read from password file %s: %s", passwordFile, err)
	}
	return string(password), nil
}
