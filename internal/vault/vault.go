package vault

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/andornaut/mrs/internal/config"
	"github.com/andornaut/mrs/internal/fs"
)

// All returns a slice of all vaults
func All() ([]Vault, error) {
	return findVaults("")
}

// Default returns the default vault.
// If a default vault name is not configured, then return the first vault found or BadVault.
// If a default vault name is configured, but cannot be found, then return an error.
func Default() (Vault, error) {
	// If DefaultVaultName is "" then findVaults() will return all vaults
	vs, err := findVaults(config.DefaultVaultName)
	if err != nil {
		return BadVault, err
	}
	if vs == nil {
		// If a default vault name is not configured, then we should not return an error, because
		// the default vault's existance is not necessarily expected.
		if config.DefaultVaultName == "" {
			return BadVault, nil
		}
		return BadVault, fmt.Errorf("Default vault \"%s\" not found", config.DefaultVaultName)
	}
	return vs[0], nil
}

// First returns the first vault to match the vault name prefix or an error
func First(prefix string) (Vault, error) {
	if prefix == "" {
		return BadVault, fmt.Errorf("vault name cannot be empty")
	}

	vs, err := findVaults(prefix)
	if err != nil {
		return BadVault, err
	}
	if vs == nil {
		return BadVault, fmt.Errorf("vault \"%s\" not found. run `mrs create-vault` to create one", prefix)
	}
	return vs[0], nil
}

// ChangePassword changes a vault's password
func ChangePassword(prefix, oldPassword, newPassword string) (UnlockedVault, error) {
	if err := validatePassword(newPassword); err != nil {
		return BadUnlockedVault, fmt.Errorf("invalid new password: %s", err)
	}
	v, err := First(prefix)
	if err != nil {
		return BadUnlockedVault, err
	}
	u := v.Unlocked(oldPassword)
	err = u.changePassword(newPassword)
	if err != nil {
		return BadUnlockedVault, err
	}
	return u, nil
}

// Create creates a vault
func Create(name, password, importFile string) (UnlockedVault, error) {
	if err := validateName(name); err != nil {
		return BadUnlockedVault, err
	}
	if err := validatePassword(password); err != nil {
		return BadUnlockedVault, err
	}

	p := toPath(name)
	exists, err := fs.IsExists(p)
	if err != nil {
		return BadUnlockedVault, err
	}
	if exists {
		return BadUnlockedVault, fmt.Errorf("a vault named \"%s\" already exists", name)
	}

	v := Vault(p).Unlocked(password)
	content := ""
	if importFile != "" {
		b, err := ioutil.ReadFile(importFile)
		if err != nil {
			return BadUnlockedVault, fmt.Errorf("could not read from import file at %s: %s", importFile, err)
		}
		content = string(b)
	}

	if err = v.Write(content); err != nil {
		return BadUnlockedVault, err
	}
	return v, nil
}

// Delete deletes a vault
func Delete(name string) error {
	if err := validateName(name); err != nil {
		return err
	}

	p := toPath(name)
	if fs.IsNotExists(p) {
		return fmt.Errorf("a vault named \"%s\" does not exist", name)
	}
	return os.Remove(p)
}

// Export writes a vault's secrets to stdout
func Export(prefix, password string) (string, error) {
	if err := validateName(prefix); err != nil {
		return "", err
	}
	v, err := First(prefix)
	if err != nil {
		return "", err
	}
	u := v.Unlocked(password)
	r, err := u.NewReader()
	if err != nil {
		return "", err
	}
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Rename renames a vault
func Rename(sourceName, targetName string) error {
	if sourceName == targetName {
		return fmt.Errorf("the source and target vault names cannot both be \"%s\"", sourceName)
	}
	if err := validateName(sourceName); err != nil {
		return err
	}
	if err := validateName(targetName); err != nil {
		return err
	}

	sourcePath := toPath(sourceName)
	targetPath := toPath(targetName)
	if err := validatePath(sourcePath); err != nil {
		return err
	}

	exists, err := fs.IsExists(targetPath)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the target path \"%s\" already exists", targetPath)
	}
	return os.Rename(sourcePath, targetPath)
}

// findVaults returns vaults that match the vault name prefix.
// If prefix is empty, then it return all vaults.
func findVaults(prefix string) ([]Vault, error) {
	var pattern string
	if prefix == "" {
		pattern = toPath("/*")
	} else {
		pattern = toPath(prefix) + "*"
	}
	matchedPaths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	var vs []Vault
	for _, p := range matchedPaths {
		if err := validatePath(p); err != nil {
			return nil, err
		}
		vs = append(vs, Vault(p))
	}
	return vs, nil
}

func toPath(n string) string {
	return path.Join(config.VaultDir, n)
}
