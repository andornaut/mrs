package vault

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/andornaut/mrs/internal/config"
	"github.com/andornaut/mrs/internal/crypto"
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
	// If DefaultVaultName is "", then findVaults() will return all vaults.
	vs, err := findVaults(config.DefaultVaultName)
	if err != nil {
		return BadVault, err
	}

	if vs == nil {
		if config.DefaultVaultName != "" {
			return BadVault, fmt.Errorf("default vault \"%s\" not found", config.DefaultVaultName)
		}
		// If a default vault name is not configured, then we should not return an error, because
		// the default vault's existance is optional.
		return BadVault, nil
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
		return BadVault, fmt.Errorf("vault \"%s\" not found. run `mrs vault create` to create one", prefix)
	}
	return vs[0], nil
}

// ChangePassword changes a vault's password
func ChangePassword(prefix, oldPassword, newPassword string) (UnlockedVault, error) {
	v, err := First(prefix)
	if err != nil {
		return BadUnlockedVault, err
	}
	if err := validatePassword(newPassword); err != nil {
		return BadUnlockedVault, fmt.Errorf("invalid new password: %s", err)
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
	var err error
	if err = validateName(name); err != nil {
		return BadUnlockedVault, err
	}
	if err = validatePassword(password); err != nil {
		return BadUnlockedVault, err
	}

	// Ensure that a legacy vault - one that does not have a salt - does not exist.
	legacyPath := toPath(name)
	exists, err := fs.IsExists(legacyPath)
	if exists {
		return BadUnlockedVault, fmt.Errorf("a vault named \"%s\" already exists", name)
	}

	var salt string
	if salt, err = crypto.Salt(); err != nil {
		return BadUnlockedVault, err
	}
	p := toPathWithSalt(name, salt)
	exists, err = fs.IsExists(p)
	if err != nil {
		return BadUnlockedVault, fmt.Errorf("a vault named \"%s\" already exists", name)
	}
	u := Vault(p).Unlocked(password)
	content := ""
	if importFile != "" {
		b, err := os.ReadFile(importFile)
		if err != nil {
			return BadUnlockedVault, fmt.Errorf("could not read from import file at %s: %s", importFile, err)
		}
		content = string(b)
	}

	if err = u.Write(content); err != nil {
		return BadUnlockedVault, err
	}
	return u, nil
}

// Delete deletes a vault
func Delete(name string) error {
	v, err := exact(name)
	if err != nil {
		return err
	}
	return os.Remove(v.Path())
}

// Export writes a vault's secrets to stdout
func Export(name, password string) (string, error) {
	v, err := exact(name)
	if err != nil {
		return "", err
	}
	u := v.Unlocked(password)
	r, err := u.NewReader()
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(r)
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
	if err := validateName(targetName); err != nil {
		return err
	}

	sourceVault, err := exact(sourceName)
	if err != nil {
		return err
	}
	var targetPath string
	salt := sourceVault.Salt()
	if salt == "" {
		// Legacy vaults do not have a per-vault salt.
		targetPath = toPath(targetName)
	} else {
		targetPath = toPathWithSalt(targetName, salt)
	}
	exists, err := fs.IsExists(targetPath)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the target path \"%s\" already exists", targetPath)
	}
	return os.Rename(sourceVault.Path(), targetPath)
}

func exact(name string) (Vault, error) {
	v, err := First(name)
	if err != nil {
		return "", err
	}
	if name != v.Name() {
		return "", fmt.Errorf("vault named \"%s\" not found. Did you mean \"%s\"?", name, v.Name())
	}
	return v, nil
}

// findVaults returns vaults that match the vault name prefix.
// If prefix is empty, then it return all vaults.
// Returns a slice with at least one vault or nil.
func findVaults(prefix string) ([]Vault, error) {
	if prefix == "" {
		prefix = "/*"
	} else {
		if err := validateName(prefix); err != nil {
			return nil, err
		}
		prefix += "*"
	}
	pattern := toPath(prefix)
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

func toPathWithSalt(n string, h string) string {
	return toPath(fmt.Sprintf("%s.%s", n, h))
}
