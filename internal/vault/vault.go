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
	var vaults []Vault
	paths, err := findPaths("")
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		if err := validatePath(p); err != nil {
			return nil, err
		}
		vaults = append(vaults, Vault(p))
	}
	return vaults, nil
}

// Default returns the default vault or nil
func Default() (Vault, error) {
	return Find("")
}

// Find returns the first vault to match the given vault name prefix.
// If the prefix is empty, then it returns the default vault.
// If it cannot find a vault and prefix is empty, then it returns empty string.
// If it cannot find a vault and prefix is not empty, then it returns an error.
func Find(prefix string) (Vault, error) {
	if prefix == "" {
		prefix = config.DefaultVaultName
	}

	paths, err := findPaths(prefix)
	if err != nil {
		return BadVault, err
	}

	if paths == nil {
		if prefix == "" {
			return BadVault, nil
		}
		return BadVault, fmt.Errorf("could not find a vault with a name that begins with \"%s\"", prefix)
	}
	p := paths[0]
	if err := validatePath(p); err != nil {
		return BadVault, err
	}
	return Vault(p), nil
}

// Create creates an UnlockedVault
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
			return BadUnlockedVault, fmt.Errorf("could not read from import file %s: %s", importFile, err)
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
	s, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(s), nil
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

func toPath(name string) string {
	return path.Join(config.VaultDir, name)
}
