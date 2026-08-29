package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/mrs/internal/config"
	"github.com/andornaut/mrs/internal/crypto"
	"github.com/andornaut/mrs/internal/fs"
)

// All returns a slice of all vaults
func All() ([]Vault, error) {
	return findVaults(true, "")
}

// AllQuiet returns every vault without reporting the ones mrs cannot read. A
// shell asking what to offer for a Tab is no place to report anything: the
// warning would land in the middle of the line being typed, on every press.
// The commands that list vaults report them, once, when the user asks.
func AllQuiet() ([]Vault, error) {
	return findVaults(false, "")
}

// errNotFound reports that no vault has or begins with the given name. The
// remedy is the caller's: Named suggests creating the vault, because a command
// that reads or writes one plausibly wants it to exist, while the commands
// that remove, rename or re-key a vault take the absence as the whole answer.
var errNotFound = errors.New("not found")

// errNoDefault reports that no vault can be the default because several exist.
// Each caller appends the remedy its own invocation has: --vault exists on the
// content commands but not on "vault default".
var errNoDefault = errors.New("several vaults exist, so there is no default")

// Default returns the vault to use when none is named: the one that
// $MRS_DEFAULT_VAULT_NAME names, or the only vault there is.
func Default() (Vault, error) {
	if name := config.DefaultVaultName(); name != "" {
		// Exactly, unlike --vault. A name written into a shell profile is read
		// on every run and looked at almost never, so a typo that reaches a
		// neighbouring vault would go on doing so unnoticed.
		vs, err := findVaults(true, name)
		if err != nil {
			return "", err
		}
		if v, ok := named(vs, name); ok {
			return v, nil
		}
		return "", fmt.Errorf(
			"default vault %q not found. $MRS_DEFAULT_VAULT_NAME must name a vault exactly", name)
	}
	vs, err := All()
	if err != nil {
		return "", err
	}
	switch len(vs) {
	case 0:
		return "", errors.New("no vaults found. Run \"mrs vault add <name>\" to create one")
	case 1:
		return vs[0], nil
	}
	// Which of several vaults a secret belongs in is not a guess worth making
	// on the user's behalf, so it is asked for rather than assumed.
	return "", fmt.Errorf("%w. Set $MRS_DEFAULT_VAULT_NAME to choose one", errNoDefault)
}

// Named returns the vault that prefix names, or the single vault whose name it
// begins, or the default vault when prefix is empty. It refuses a prefix that
// could have meant more than one vault: choosing between them alphabetically
// would read one vault while the user meant another, and write to one while
// they meant another.
//
// It is the one way a command resolves a vault by name or prefix: --path
// names one outright through AtPath, and the commands that create, destroy or
// move a vault take a whole name and use Exact.
func Named(prefix string) (Vault, error) {
	if prefix == "" {
		v, err := Default()
		if errors.Is(err, errNoDefault) {
			return "", fmt.Errorf("%w. Use --vault to name one, or set $MRS_DEFAULT_VAULT_NAME", errNoDefault)
		}
		return v, err
	}
	v, matched, err := resolve(prefix)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return "", fmt.Errorf("%w. Run \"mrs vault add <name>\" to create one", err)
		}
		return "", err
	}
	if len(matched) > 1 && v.Name() != prefix {
		return "", fmt.Errorf("%q begins the name of %d vaults: %s. Use the whole name of the one you mean",
			prefix, len(matched), strings.Join(names(matched), ", "))
	}
	return v, nil
}

// AtPath returns the vault stored at p, wherever that is: on removable media,
// in a directory that is synced elsewhere, or anywhere else outside the vault
// directory. It names one vault outright, so it takes no prefix and has no
// default to fall back on.
//
// The filename still has to be <name>.<salt>, because a vault's key is derived
// from the salt its filename carries and there is nowhere else to read it
// from. The lock, the backup and the temporary files of an atomic write are
// its siblings, so mrs writes in the directory the vault is in.
func AtPath(p string) (Vault, error) {
	if p == "" {
		return "", errors.New("vault path cannot be empty")
	}
	// Absolute, so that the vault has one identity in what is reported and in
	// the lock file, backup and temporary files named after it.
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("could not resolve vault path %q: %w", p, err)
	}
	// The filename is checked before the file is looked for, so that a path
	// that could not name a vault whatever is on disk says so, rather than
	// being reported as a vault that is missing.
	if err := validateFilename(filepath.Base(abs)); err != nil {
		return "", fmt.Errorf("%q does not name a vault: %w. A vault file is named <name>.<salt>", p, err)
	}
	if err := validatePath(abs); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("vault %q not found", p)
		}
		return "", fmt.Errorf("vault %q cannot be read: %w", p, err)
	}
	return Vault(abs), nil
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
		return "", nil, errors.New("vault name cannot be empty")
	}
	vs, err := findVaults(true, prefix)
	if err != nil {
		return "", nil, err
	}
	if vs == nil {
		return "", nil, fmt.Errorf("vault %q %w", prefix, errNotFound)
	}
	if v, ok := named(vs, prefix); ok {
		return v, vs, nil
	}
	return vs[0], vs, nil
}

// named returns the vault whose name is exactly name, which a prefix match
// finds alongside every longer name that begins with it. The exact match is
// chosen rather than the first of them, so that a vault named "work" is never
// read or written as "work-archive" whenever both exist.
func named(vs []Vault, name string) (Vault, bool) {
	for _, v := range vs {
		if v.Name() == name {
			return v, true
		}
	}
	return "", false
}

// ChangePassword changes a vault's password, re-keying it under the new one.
func ChangePassword(oldPassword, newPassword []byte, v Vault) (UnlockedVault, error) {
	if err := ValidateNewPassword(newPassword); err != nil {
		return UnlockedVault{}, err
	}
	u := v.Unlocked(oldPassword)
	if err := u.changePassword(newPassword); err != nil {
		return UnlockedVault{}, err
	}
	return u, nil
}

// claimName takes the lock on name and confirms that no vault holds the name,
// returning the unlock the caller releases once its write is done. The lock
// comes first, because the answer only decides anything while nothing else can
// claim the name between the question and that write: without it, a concurrent
// create or rename of the same name leaves two vault files carrying it, which
// every command that resolves a name then picks between by listing order. The
// lock is never taken from another process, only repaired if its file cannot
// be used.
//
// Exists is asked about the name rather than the path, because a vault carries
// a salt of its own in its filename and so never collides with the path of an
// existing vault of the same name.
func claimName(repair bool, name string) (func(), error) {
	// Asked once before the lock, so that a name that is already a vault's is
	// answered as that rather than as whatever state its lock happens to be
	// in: a held lock on a taken name means someone is writing that vault, not
	// that the name might come free. The check under the lock below is the
	// answer that decides for a name that is free.
	if exists, err := Exists(name); err != nil {
		return nil, err
	} else if exists {
		return nil, fmt.Errorf("a vault named %q already exists", name)
	}
	p, err := toPath(name)
	if err != nil {
		return nil, err
	}
	unlock, err := Vault(p).ExclusiveLockRepair(repair)
	if err != nil {
		return nil, err
	}
	exists, err := Exists(name)
	if err != nil {
		unlock()
		return nil, err
	}
	if exists {
		unlock()
		return nil, fmt.Errorf("a vault named %q already exists", name)
	}
	return unlock, nil
}

// Create creates a vault holding the given secrets, which may be empty. The
// caller reads and validates any import file, so that a vault is never created
// from contents that mrs cannot read back.
//
// The password is asked for through a function rather than passed in, so that
// the name's lock is claimed before anyone types one: nobody enters a password
// for a name another process is claiming. Create owns what the function
// returns, wiping it on failure; on success the returned UnlockedVault carries
// it and Wipe wipes it.
func Create(contents []byte, repair bool, name string, password func() ([]byte, error)) (UnlockedVault, error) {
	if err := ValidateName(name); err != nil {
		return UnlockedVault{}, err
	}
	unlock, err := claimName(repair, name)
	if err != nil {
		return UnlockedVault{}, err
	}
	defer unlock()

	pw, err := password()
	if err != nil {
		return UnlockedVault{}, err
	}
	created := false
	defer func() {
		if !created {
			crypto.Wipe(pw)
		}
	}()
	if err = ValidatePassword(pw); err != nil {
		return UnlockedVault{}, err
	}

	salt, err := crypto.Salt()
	if err != nil {
		return UnlockedVault{}, err
	}
	p, err := toPathWithSalt(name, salt)
	if err != nil {
		return UnlockedVault{}, err
	}
	u := Vault(p).Unlocked(pw)
	if err = u.Write(contents); err != nil {
		return UnlockedVault{}, err
	}
	created = true
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
	if err := fs.RemoveTempFiles(v.Path()); err != nil {
		warnf("failed to remove temporary files for vault %s: %s", v.Name(), err)
	}
	if err := os.Remove(v.backupPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("deleted vault %s but failed to remove its backup, which still contains your secrets: %w", v.Name(), err)
	}
	return nil
}

// Rename renames a vault. The caller holds the source vault's lock; the target
// name is locked here. repair applies to both alike, and to neither does it
// mean taking a lock another process holds.
func Rename(targetName string, repair bool, sourceVault Vault) error {
	sourceName := sourceVault.Name()
	if sourceName == targetName {
		return fmt.Errorf("the source and target vault names cannot both be %q", sourceName)
	}
	if err := ValidateName(targetName); err != nil {
		return err
	}

	// The source is locked under a different name, so the two locks cannot be
	// the same one, and both are taken without blocking.
	unlock, err := claimName(repair, targetName)
	if err != nil {
		return err
	}
	defer unlock()

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
	if err := fs.RemoveTempFiles(sourceVault.Path()); err != nil {
		warnf("failed to remove temporary files for vault %s: %s", sourceName, err)
	}
	if err := os.Rename(sourceVault.backupPath(), Vault(targetPath).backupPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("renamed vault %s to %s but failed to move its backup, which still contains your secrets under the old name: %w", sourceName, targetName, err)
	}
	return nil
}

// warnf prints a best-effort warning to stderr for cleanup failures that must
// not fail the surrounding operation.
func warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Warning: "+format+"\n", args...)
}

// Exists reports whether a vault file with exactly the given name is there,
// whatever salt its filename carries. claimName asks before taking the name's
// lock and again under it, for Create and Rename alike; the under-lock answer
// is the one that decides.
//
// It asks of the filename rather than of the contents. A file mrs cannot read
// still occupies the name: a symlink whose target is not mounted, or a vault at
// a key derivation this version does not support. Handing the name out again
// would leave two files carrying it, which is what every command that resolves
// a name would then have to choose between.
func Exists(name string) (bool, error) {
	// Validated here as well as by findVaults, so that an invalid name is an
	// error rather than a name that merely fails to exist.
	if err := ValidateName(name); err != nil {
		return false, err
	}
	// findVaults owns what counts as a vault file, and is asked quietly: an
	// existence check is no place to warn about entries that cannot be read.
	vs, err := findVaults(false, name)
	if err != nil {
		return false, err
	}
	_, ok := named(vs, name)
	return ok, nil
}

// Exact returns the vault named exactly name, or an error naming the closest
// match. Commands that destroy or move a vault resolve with this rather than
// Named, so that a prefix cannot reach a neighbouring vault.
func Exact(name string) (Vault, error) {
	// Resolved without Named, so that an ambiguous prefix is reported once, as
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

// findVaults returns the vaults whose names begin with prefix, or every vault
// when prefix is empty. Returns a slice with at least one vault or nil.
//
// A vault mrs cannot read is listed either way; warn says whether the reason is
// reported, which a shell completion does not want.
func findVaults(warn bool, prefix string) ([]Vault, error) {
	if prefix != "" {
		if err := ValidateName(prefix); err != nil {
			return nil, err
		}
	}
	matchedPaths, err := matchVaultFiles(prefix)
	if err != nil {
		return nil, err
	}

	var vs []Vault
	for _, p := range matchedPaths {
		// Skip lock, backup, and leftover temporary files
		base := filepath.Base(p)
		ext := filepath.Ext(base)
		if ext == lockSuffix || ext == backupSuffix || ext == fs.TempSuffix {
			continue
		}
		// Skip stray files that do not match the vault filename shape instead of
		// failing the listing, but say so, so that a vault whose file was
		// renamed by hand does not disappear without explanation. Hidden files
		// (.DS_Store, editor swap files) are never vaults, so they are skipped
		// quietly.
		if err := validateFilename(base); err != nil {
			if warn && !strings.HasPrefix(base, ".") {
				warnf("ignoring %q, because a vault file is named <name>.<salt>", p)
			}
			continue
		}
		// A vault mrs cannot read is a vault like any other: it is listed,
		// holds its name, and can be renamed or deleted; only the commands that
		// have to read it fail, exactly as they do for a vault written at a key
		// derivation mrs no longer supports. The warning says why, because the
		// entry is there and the reason it cannot be read is not.
		//
		// Failing the whole listing instead would take out every other vault
		// over one bad entry, and leave no way to remove the bad entry with
		// mrs.
		if err := validatePath(p); err != nil {
			// The one entry that is not listed is one that is no longer there:
			// a vault can vanish between reading the directory and the stat if
			// another process deletes it, which is nothing to report and
			// nothing to list. A vault present as a symlink whose target is
			// not there is the other case, and is listed.
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if warn {
				warnf("vault %s cannot be read: %s", Vault(p).Name(), err)
			}
		}
		vs = append(vs, Vault(p))
	}
	// Sorted by name ignoring case, as secrets are sorted by key, so that both
	// listings read the same way. Filename order would put every uppercase name
	// ahead of every lowercase one, and "_under" between "Banana" and "mango".
	//
	// Stable, so that names differing only in case keep the order they arrived
	// in and a listing does not change between runs. An unstable sort would
	// need a byte-order tiebreak to say the same thing, and that tiebreak can
	// never fire: os.ReadDir returns filenames in byte order already.
	slices.SortStableFunc(vs, func(a, b Vault) int {
		return strings.Compare(strings.ToLower(a.Name()), strings.ToLower(b.Name()))
	})
	return vs, nil
}

// matchVaultFiles returns the paths in the vault directory whose filenames
// begin with prefix, in filename order.
//
// filepath.Glob is not used, because it reports a directory it could not read
// as no matches at all. A vault directory whose mode or ownership keeps mrs out
// would be answered with "no vaults found", which is the wrong answer to a
// directory that could not be looked in and reads as though the vaults were
// gone.
func matchVaultFiles(prefix string) ([]string, error) {
	dir, err := config.GetVaultDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("could not read the vault directory %q: %w", dir, err)
	}
	var ps []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		ps = append(ps, filepath.Join(dir, e.Name()))
	}
	return ps, nil
}

func toPath(n string) (string, error) {
	vaultDir, err := config.GetVaultDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(vaultDir, n), nil
}

func toPathWithSalt(n string, salt string) (string, error) {
	return toPath(n + "." + salt)
}
