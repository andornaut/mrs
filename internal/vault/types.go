package vault

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
)

// Vault is a secrets store
type Vault string

var (
        // BadVault is an invalid Vault
        BadVault Vault
        // BadUnlockedVault is an invalid UnlockedVault
        BadUnlockedVault UnlockedVault
)

// Name returns the name of the vault
func (v Vault) Name() string {
	if v == BadVault {
		return ""
	}
	return filepath.Base(v.Path())
}

// Path returns the absolute file path to the vault
func (v Vault) Path() string {
	return string(v)
}

func (v Vault) String() string {
	return v.Name()
}

// Unlocked returns a UnlockedVault
func (v Vault) Unlocked(password string) UnlockedVault {
	return UnlockedVault{v, password}
}

const preample = "# Secrets \"vault\" managed by Mr. Secretary: github.com/andornaut/mrs\n"

// UnlockedVault is a vault that can be read from and written to
type UnlockedVault struct {
	Vault
	password string
}

func (v *UnlockedVault) changePassword(p string) error {
        r, err := v.NewReader()
        if err != nil {
                return err
        }
        b, err := ioutil.ReadAll(r)
        if err != nil {
                return err
        }
        v.password = p
        return v.Write(string(b))
}

// NewReader returns a io.Reader reading from the vault
func (v *UnlockedVault) NewReader() (io.Reader, error) {
	b, err := ioutil.ReadFile(v.Path())
	if err != nil {
		return nil, err
	}
	b, err = decrypt(b, v.password)
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt vault %s", v)
	}
	return bytes.NewReader(b), nil
}

// Write writes the given string to the vault
func (v *UnlockedVault) Write(s string) error {
	b := []byte(preample + s)
	b, err := encrypt(b, v.password)
	if err != nil {
		return fmt.Errorf("Failed to encrypt secrets. Vault %s is unchanged", v)
	}
	return ioutil.WriteFile(v.Path(), b, 0600)
}
