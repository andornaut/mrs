package vault

import (
	"errors"
	"fmt"
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

// Default returns the vault to use when none is named: the one that
// $MRS_DEFAULT_VAULT_NAME names, or the only vault there is. It returns
// BadVault without an error when there are no vaults at all, because a vault
// directory that is still empty is not a misconfiguration.
func Default() (Vault, error) {
	if config.DefaultVaultName != "" {
		// Exactly, unlike --vault. A name written into a shell profile is read
		// on every run and looked at almost never, so a typo that reaches a
		// neighbouring vault would go on doing so unnoticed.
		vs, err := findVaults(config.DefaultVaultName)
		if err != nil {
			return BadVault, err
		}
		if v, ok := named(vs, config.DefaultVaultName); ok {
			return v, nil
		}
		return BadVault, fmt.Errorf(
			"default vault %q not found. $MRS_DEFAULT_VAULT_NAME must name a vault exactly",
			config.DefaultVaultName)
	}
	vs, err := All()
	if err != nil {
		return BadVault, err
	}
	switch len(vs) {
	case 0:
		return BadVault, nil
	case 1:
		return vs[0], nil
	}
	// Which of several vaults a secret belongs in is not a guess worth making
	// on the user's behalf, so it is asked for rather than assumed.
	return BadVault, errors.New(
		"several vaults exist, so there is no default. Use --vault to name one, or set $MRS_DEFAULT_VAULT_NAME")
}

// Named returns the vault that prefix names, or the default vault when prefix
// is empty. It is the one way a command names a vault it does not destroy or
// move; those use Exact.
func Named(prefix string) (Vault, error) {
	if prefix == "" {
		return orDefault()
	}
	return Unique(prefix)
}

func orDefault() (Vault, error) {
	v, err := Default()
	if err != nil {
		return BadVault, err
	}
	if v == BadVault {
		// Default returns BadVault without an error only when there are no
		// vaults, so there is no name the user could give that would help.
		return BadVault, errors.New("no vaults found. Run \"mrs vault create\" to create one")
	}
	return v, nil
}

// Unique returns the vault that prefix names, or the single vault whose name it
// begins, and refuses a prefix that could have meant more than one. Choosing
// between them alphabetically would read one vault while the user meant
// another, and write to one while they meant another.
func Unique(prefix string) (Vault, error) {
	v, matched, err := resolve(prefix)
	if err != nil {
		return BadVault, err
	}
	if len(matched) > 1 && v.Name() != prefix {
		return BadVault, fmt.Errorf("%q begins the name of %d vaults: %s. Use the whole name of the one you mean",
			prefix, len(matched), strings.Join(names(matched), ", "))
	}
	return v, nil
}

// names returns the vaults' names, in the order they were matched.
func names(vs []Vault) []string {
	ns := make([]string, 0, len(vs))
	for _, v := range vs {
		ns = append(ns, v.Name())
	}
	return ns
}

// resolve returns the vault that prefix selects, along with every vault it
// matched, so that a caller can tell an exact name from an ambiguous prefix.
func resolve(prefix string) (Vault, []Vault, error) {
	if prefix == "" {
		return BadVault, nil, fmt.Errorf("vault name cannot be empty")
	}
	vs, err := findVaults(prefix)
	if err != nil {
		return BadVault, nil, err
	}
	if vs == nil {
		return BadVault, nil, fmt.Errorf("vault %q not found. Run \"mrs vault create\" to create one", prefix)
	}
	if v, ok := named(vs, prefix); ok {
		return v, vs, nil
	}
	return vs[0], vs, nil
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
func ChangePassword(v Vault, oldPassword, newPassword []byte) (UnlockedVault, error) {
	if err := validatePassword(newPassword); err != nil {
		return BadUnlockedVault, fmt.Errorf("invalid new password: %w", err)
	}
	u := v.Unlocked(oldPassword)
	if err := u.changePassword(newPassword); err != nil {
		return BadUnlockedVault, err
	}
	return u, nil
}

// Create creates a vault holding the given secrets, which may be empty. The
// caller reads and validates any import file, so that a vault is never created
// from contents that mrs cannot read back.
func Create(name string, password, contents []byte, force bool) (UnlockedVault, error) {
	if err := ValidateName(name); err != nil {
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
	exists, err := Exists(name)
	if err != nil {
		return BadUnlockedVault, err
	}
	if exists {
		return BadUnlockedVault, fmt.Errorf("a vault named %q already exists", name)
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
	if err = u.Write(contents); err != nil {
		return BadUnlockedVault, err
	}
	return u, nil
}

// Delete deletes a vault, along with its backup and temporary files
func Delete(v Vault) error {
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

// Export returns a vault's secrets. The caller resolves the vault, so that
// export reports a name it cannot find the way every other command does, and
// is responsible for wiping the returned slice.
func Export(v Vault, password []byte) ([]byte, error) {
	u := v.Unlocked(password)
	defer u.Wipe()
	return u.Decrypt()
}

// Rename renames a vault
func Rename(sourceVault Vault, targetName string) error {
	sourceName := sourceVault.Name()
	if sourceName == targetName {
		return fmt.Errorf("the source and target vault names cannot both be %q", sourceName)
	}
	if err := ValidateName(targetName); err != nil {
		return err
	}
	// Comparing paths is not enough, because the target keeps the source's salt
	// and so never collides with the path of an existing vault of the same name.
	exists, err := Exists(targetName)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("a vault named %q already exists", targetName)
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

// Exists reports whether a vault with exactly the given name exists, whatever
// salt its filename carries. A command may use it to refuse early, but Create
// asks again while holding the lock, which is the answer that decides.
func Exists(name string) (bool, error) {
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
	// Resolved without First, so that an ambiguous prefix is reported once, as
	// the error below, rather than also as a warning about a vault that is
	// about to be refused.
	v, _, err := resolve(name)
	if err != nil {
		return "", err
	}
	if name != v.Name() {
		return "", fmt.Errorf("vault %q not found. Did you mean %q?", name, v.Name())
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
		if err := ValidateName(prefix); err != nil {
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
				warnf("ignoring %q, because a vault file is named <name>.<salt>", p)
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
