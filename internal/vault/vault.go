package vault

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/andornaut/mrs/internal/config"
	"github.com/andornaut/mrs/internal/crypto"
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
	if v, ok := named(vs, config.DefaultVaultName); ok {
		return v, nil
	}
	return vs[0], nil
}

// First returns the vault named prefix, or the first vault whose name begins
// with it, or an error.
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
	if v, ok := named(vs, prefix); ok {
		return v, nil
	}
	return vs[0], nil
}

// named returns the vault whose name is exactly name. A vault is matched by a
// glob on its name, so a shorter name is always matched alongside every longer
// one that begins with it. Without preferring the exact match, a vault named
// "work" is read and written as "work-archive" whenever both exist, because a
// "-" sorts before the "." that separates a name from its salt.
func named(vs []Vault, name string) (Vault, bool) {
	for _, v := range vs {
		if v.Name() == name {
			return v, true
		}
	}
	return BadVault, false
}

// ChangePassword changes a vault's password. It re-keys the vault, so it takes
// the whole name rather than a prefix that could reach a neighbouring one.
func ChangePassword(name string, oldPassword, newPassword []byte) (UnlockedVault, error) {
	v, err := Exact(name)
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

// Create creates a vault holding the given secrets, which may be empty. The
// caller reads and validates any import file, so that a vault is never created
// from contents that mrs cannot read back.
func Create(name string, password, contents []byte, force bool) (UnlockedVault, error) {
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
	unlock, err := Vault(p).ExclusiveLockForce(force)
	if err != nil {
		return BadUnlockedVault, err
	}
	defer unlock()

	// Ensure that no vault of this name exists. Comparing paths is not enough,
	// because a new vault is given a fresh random salt and so never collides
	// with the path of an existing vault of the same name.
	exists, err := existsByName(name)
	if err != nil {
		return BadUnlockedVault, err
	}
	if exists {
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
	u := Vault(p).Unlocked(password)
	if err = u.Write(string(contents)); err != nil {
		return BadUnlockedVault, err
	}
	return u, nil
}

// Delete deletes a vault, along with its backup and temporary files
func Delete(name string) error {
	v, err := Exact(name)
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

// Export writes a vault's secrets to stdout. Reading a vault does not change
// it, so a name prefix is enough, as it is for search.
func Export(prefix string, password []byte) (string, error) {
	v, err := First(prefix)
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

	sourceVault, err := Exact(sourceName)
	if err != nil {
		return err
	}
	// Comparing paths is not enough, because the target keeps the source's salt
	// and so never collides with the path of an existing vault of the same name.
	exists, err := existsByName(targetName)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("a vault named \"%s\" already exists", targetName)
	}
	// The target keeps the source's salt, because renaming does not decrypt.
	targetPath, err := toPathWithSalt(targetName, sourceVault.Salt())
	if err != nil {
		return err
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

// existsByName reports whether a vault with exactly the given name exists,
// whatever salt its filename carries.
func existsByName(name string) (bool, error) {
	vs, err := findVaults(name)
	if err != nil {
		return false, err
	}
	for _, v := range vs {
		if v.Name() == name {
			return true, nil
		}
	}
	return false, nil
}

// Exact returns the vault named exactly name, or an error naming the closest
// match. Commands that destroy or move a vault resolve with this rather than
// First, so that a prefix cannot reach a neighbouring vault.
func Exact(name string) (Vault, error) {
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
		// Skip stray files that do not match the vault filename shape instead of
		// failing the listing, but say so, so that a vault whose file was
		// renamed by hand does not disappear without explanation. Hidden files
		// (.DS_Store, editor swap files) are never vaults, so they are skipped
		// quietly.
		if err := validateFilename(base); err != nil {
			if !strings.HasPrefix(base, ".") {
				warnf("ignoring \"%s\", because a vault file is named <name>.<salt>", p)
			}
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
