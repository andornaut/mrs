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
	paths, err := findPaths("")
	if err != nil {
		return nil, err
	}

        var vaults []Vault
	for _, p := range paths {
                var (
                        v   Vault
                        err error
                )
                if v, err = toVault(p); err != nil {
			return nil, err
		}
                vaults = append(vaults, v)

	}
	return vaults, nil
}

// Default returns the default vault.
// If a default vault name is not configured, then return the first vault found or BadVault.
// If a default vault name is configured, but cannot be found, then return an error.
func Default() (Vault, error) {
        paths, err := findPaths(config.DefaultVaultName)
        if err != nil {
                return BadVault, err
        }
        if paths == nil {
                // If a default vault name is not configured, then we should not return an error, because
                // the default vault's existance is not necessarily expected.
                if config.DefaultVaultName == "" {
                        return BadVault, nil
                }
                return BadVault, fmt.Errorf("Default vault \"%s\" not found", config.DefaultVaultName)
        }
        return toVault(paths[0])
}

// Find returns the first vault to match the vault name prefix or an error
func Find(prefix string) (Vault, error) {
	if prefix == "" {
                return BadVault, fmt.Errorf("vault name cannot be empty")
	}

	paths, err := findPaths(prefix)
	if err != nil {
		return BadVault, err
	}
	if paths == nil {
                return BadVault, fmt.Errorf("vault \"%s\" not found. run `mrs create-vault` to create one", prefix)
	}
        return toVault(paths[0])
}

// ChangePassword changes a vault's password
func ChangePassword(name, oldPassword, newPassword string) (UnlockedVault, error) {
        v, err := Find(name)
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
		content = string(b)
		if err != nil {
                        return BadUnlockedVault, fmt.Errorf("could not read from import file at %s: %s", importFile, err)
		}
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
	if err := os.Remove(p); err != nil {
		return err
	}
	return nil
}

// Export writes a vault's secrets to stdout
func Export(name, password string) (string, error) {
	if err := validateName(name); err != nil {
		return "", err
	}
	v, err := Find(name)
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

	if err := os.Rename(sourcePath, targetPath); err != nil {
		return err
	}
	return nil
}

// vaultpaths returns file paths that match the given prefix.
// If prefix is empty, then this will return the all paths.
func findPaths(prefix string) ([]string, error) {
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
	return matchedPaths, nil
}

func toPath(n string) string {
        return path.Join(config.VaultDir, n)
}

func toVault(p string) (Vault, error) {
        if err := validatePath(p); err != nil {
                return BadVault, err
        }
        return Vault(p), nil
}
