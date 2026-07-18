package vault

import (
	"errors"
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
		// the default vault's existence is optional.
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
func ChangePassword(prefix string, oldPassword, newPassword []byte) (UnlockedVault, error) {
	v, err := First(prefix)
	if err != nil {
		return BadUnlockedVault, err
	}
	if err = validatePassword(newPassword); err != nil {
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
func Create(name string, password []byte, importFile string) (UnlockedVault, error) {
	if err := validateName(name); err != nil {
		return BadUnlockedVault, err
	}
	if err := validatePassword(password); err != nil {
		return BadUnlockedVault, err
	}

	// Lock the vault name before creating files.
	// We use toPath(name) to get a base path for the lock file.
	p, err := toPath(name)
	if err != nil {
		return BadUnlockedVault, err
	}
	unlock, err := Vault(p).ExclusiveLock()
	if err != nil {
		return BadUnlockedVault, err
	}
	defer unlock()

	// Ensure that a legacy vault - one that does not have a salt - does not exist.
	legacyPath, err := toPath(name)
	if err != nil {
		return BadUnlockedVault, err
	}
	var exists bool
	if exists, err = fs.IsExists(legacyPath); err != nil {
		return BadUnlockedVault, err
	} else if exists {
		return BadUnlockedVault, fmt.Errorf("a vault named \"%s\" already exists", name)
	}

	salt, err := crypto.Salt()
	if err != nil {
		return BadUnlockedVault, err
	}
	p, err = toPathWithSalt(name, salt)
	if err != nil {
		return BadUnlockedVault, err
	}
	exists, err = fs.IsExists(p)
	if err != nil {
		return BadUnlockedVault, err
	} else if exists {
		return BadUnlockedVault, fmt.Errorf("a vault named \"%s\" already exists", name)
	}
	u := Vault(p).Unlocked(password)
	content := ""
	if importFile != "" {
		var b []byte
		b, err = os.ReadFile(importFile)
		if err != nil {
			return BadUnlockedVault, fmt.Errorf("could not read from import file at %s: %s", importFile, err)
		}
		defer crypto.Wipe(b)
		content = string(b)
	}

	if err = u.Write(content); err != nil {
		return BadUnlockedVault, err
	}
	return u, nil
}

// Delete deletes a vault, along with its backup and temporary files
func Delete(name string) error {
	v, err := exact(name)
	if err != nil {
		return err
	}
	if err := os.Remove(v.Path()); err != nil {
		return err
	}
	// The vault itself is gone. Removing the temporary files is best-effort and
	// only warns, but a leftover backup still holds the secrets, so failing to
	// remove it is reported as an error that makes clear the vault was deleted.
	// The lock file is left in place, as by other commands, and is harmless
	// because it is re-lockable once no process holds it.
	if err := removeTempFiles(v.Path()); err != nil {
		warnf("failed to remove temporary files for vault %s: %s", v.Name(), err)
	}
	if err := os.Remove(v.Path() + ".bak"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("deleted vault %s but failed to remove its backup, which still contains your secrets: %w", v.Name(), err)
	}
	return nil
}

// Export writes a vault's secrets to stdout
func Export(name string, password []byte) (string, error) {
	v, err := exact(name)
	if err != nil {
		return "", err
	}
	u := v.Unlocked(password)
	defer u.Wipe()
	r, err := u.NewReader()
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	defer crypto.Wipe(b)
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
		targetPath, err = toPath(targetName)
	} else {
		targetPath, err = toPathWithSalt(targetName, salt)
	}
	if err != nil {
		return err
	}
	var exists bool
	exists, err = fs.IsExists(targetPath)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the target path \"%s\" already exists", targetPath)
	}
	if err := os.Rename(sourceVault.Path(), targetPath); err != nil {
		return err
	}
	// The vault itself is renamed. Removing the temporary files is best-effort
	// and only warns, but the backup still holds the secrets, so failing to move
	// it out from under the old name is reported as an error that makes clear
	// the vault was renamed. The lock file is left in place, as by other
	// commands, and is harmless because it is re-lockable once no process holds
	// it.
	if err := removeTempFiles(sourceVault.Path()); err != nil {
		warnf("failed to remove temporary files for vault %s: %s", sourceVault.Name(), err)
	}
	if err := os.Rename(sourceVault.Path()+".bak", targetPath+".bak"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("renamed vault %s to %s but failed to move its backup, which still contains your secrets under the old name: %w", sourceName, targetName, err)
	}
	return nil
}

// warnf prints a best-effort warning to stderr for cleanup failures that must
// not fail the surrounding operation.
func warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Warning: "+format+"\n", args...)
}

// removeTempFiles removes leftover temporary files from interrupted or failed
// atomic writes of the vault at vaultPath.
func removeTempFiles(vaultPath string) error {
	matches, err := filepath.Glob(vaultPath + ".*.tmp")
	if err != nil {
		return err
	}
	var errs []error
	for _, m := range matches {
		if err := os.Remove(m); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
	pattern, err := toPath(prefix)
	if err != nil {
		return nil, err
	}
	matchedPaths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	var vs []Vault
	for _, p := range matchedPaths {
		// Skip lock, backup, and leftover temporary files
		base := filepath.Base(p)
		ext := filepath.Ext(base)
		if ext == ".lock" || ext == ".bak" || ext == ".tmp" {
			continue
		}
		// Skip stray files that do not match the vault filename shape
		// (e.g. .DS_Store, editor swap files) instead of failing the listing.
		if err := validateNameWithOptionalSalt(base); err != nil {
			continue
		}
		// A file that has a vault-shaped name but cannot be stat'd or is a
		// directory is a real problem: surface it instead of hiding the vault.
		// A vault can vanish between the glob and this stat if another process
		// deletes it concurrently, so skip that case rather than failing the
		// whole listing.
		if err := validatePath(p); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		vs = append(vs, Vault(p))
	}
	return vs, nil
}

func toPath(n string) (string, error) {
	vaultDir, err := config.GetVaultDir()
	if err != nil {
		return "", err
	}
	return path.Join(vaultDir, n), nil
}

func toPathWithSalt(n string, h string) (string, error) {
	return toPath(fmt.Sprintf("%s.%s", n, h))
}
