package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofrs/flock"

	"github.com/andornaut/mrs/internal/crypto"
	"github.com/andornaut/mrs/internal/fs"
)

// Vault is a secrets store, held as the path of the file it is stored in. The
// zero value names no vault, and is what every function here returns alongside
// an error.
type Vault string

// Name returns the name of the vault
func (v Vault) Name() string {
	if v == "" {
		return ""
	}
	// basename must contain 0 or 1 "." characters.
	return strings.SplitN(v.basename(), ".", 2)[0]
}

// Salt returns a salt derived from the filename or empty string if one does not exist.
func (v Vault) Salt() string {
	if v == "" {
		return ""
	}
	// basename must contain 0 or 1 "." characters.
	arr := strings.SplitN(v.basename(), ".", 2)
	if len(arr) == 1 {
		return ""
	}
	return arr[1]
}

// Path returns the absolute file path to the vault
func (v Vault) Path() string {
	return string(v)
}

func (v Vault) String() string {
	return v.Name()
}

// Unlocked returns a UnlockedVault
func (v Vault) Unlocked(password []byte) UnlockedVault {
	return UnlockedVault{v, password}
}

// ErrLockHeld reports that another process holds the vault's lock. It is the
// one lock failure that repairing cannot help with, and callers test for it so
// that they do not offer a remedy that is not one.
var ErrLockHeld = errors.New("locked by another process")

// ErrLockUnusable reports that the vault's lock file could not be opened, as a
// file whose mode forbids it or a directory left in its place cannot be. This
// is what --force repairs.
var ErrLockUnusable = errors.New("the lock file cannot be used")

// ExclusiveLock acquires an exclusive lock on the vault.
// It returns an unlock function and any error encountered.
func (v Vault) ExclusiveLock() (func(), error) {
	if v == "" {
		return nil, errors.New("cannot lock a vault with no name")
	}
	f := flock.New(v.lockPath())
	locked, err := f.TryLock()
	if err != nil {
		return nil, fmt.Errorf("%w for vault %s: %w", ErrLockUnusable, v.Name(), err)
	}
	if !locked {
		return nil, fmt.Errorf("vault %s is currently %w", v.Name(), ErrLockHeld)
	}
	return func() { _ = f.Unlock() }, nil
}

// ExclusiveLockRepair is ExclusiveLock, and when repair is true it first makes
// a lock file that cannot be used usable again.
//
// Repairing is not taking. A lock another process holds is refused whether or
// not repair was asked for, because the only way past a held lock is to remove
// the lock file, which leaves the two processes holding two different files and
// each believing the vault is theirs. That is true of the lock on a vault and
// of the lock a name is claimed under alike, so neither is ever taken from
// anyone: what a caller can ask for is that an unusable lock file be made
// usable, after which the lock decides as it always does.
//
// Repairing therefore keeps the lock file's identity wherever there is one to
// keep, so that a process already holding it goes on holding it.
func (v Vault) ExclusiveLockRepair(repair bool) (func(), error) {
	unlock, err := v.ExclusiveLock()
	if err == nil || !repair {
		return unlock, err
	}
	if errors.Is(err, ErrLockHeld) {
		// Say why the flag did not help, rather than repeat a refusal that
		// looks the same as the one given without it.
		return nil, fmt.Errorf(
			"%w. --force repairs a lock file that cannot be used, and does not take a lock another process holds", err)
	}
	if !errors.Is(err, ErrLockUnusable) {
		return nil, err
	}
	if repairErr := v.repairLock(); repairErr != nil {
		return nil, repairErr
	}
	return v.ExclusiveLock()
}

// repairLock makes an unusable lock file usable, without changing what holds
// it. A file is chmod'd rather than removed, so that its identity survives and
// a lock another process took on it survives with it. Two things are removed
// instead, because neither can be opened and so neither can be held by anyone:
// a directory in the lock's place, and a symlink to a file that is not there. A
// platform that locks a directory instead - Darwin does - has already excluded
// everyone else and never gets here.
func (v Vault) repairLock() error {
	if v == "" {
		return errors.New("cannot repair the lock on a vault with no name")
	}
	p := v.lockPath()
	fi, err := os.Lstat(p)
	if err != nil {
		if os.IsNotExist(err) {
			// Nothing to repair. The lock file is created by taking the lock.
			return nil
		}
		return fmt.Errorf("could not repair the lock on vault %s: %w", v.Name(), err)
	}
	if fi.IsDir() {
		if err := os.Remove(p); err != nil {
			return fmt.Errorf("could not remove the directory in place of the lock on vault %s: %w", v.Name(), err)
		}
		return nil
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		// Any symlink that does not resolve: one whose target is not there, one
		// that points into a directory nothing may enter, and one that loops.
		// A chmod would follow the link and fail on the target exactly as the
		// lock did, so the link is removed and the lock file created afresh.
		// One that does resolve is left to the chmod below, which reaches the
		// target the lock is taken on.
		if _, statErr := os.Stat(p); statErr != nil {
			if err := os.Remove(p); err != nil {
				return fmt.Errorf(
					"could not remove the broken symlink in place of the lock on vault %s: %w", v.Name(), err)
			}
			return nil
		}
	}
	if err := os.Chmod(p, 0600); err != nil {
		return fmt.Errorf("could not repair the lock on vault %s: %w", v.Name(), err)
	}
	return nil
}

func (v Vault) lockPath() string {
	return filepath.Join(filepath.Dir(v.Path()), v.Name()+".lock")
}

func (v Vault) basename() string {
	return filepath.Base(v.Path())
}

// UnlockedVault is a vault that can be read from and written to
type UnlockedVault struct {
	Vault

	password []byte
}

// Decrypt returns the vault's plaintext. The caller owns the returned slice and
// is responsible for wiping it. It is returned rather than wrapped in a reader
// so that no copy of the plaintext exists without an owner that can wipe it: a
// bytes.Reader hides the buffer it reads from, and nothing could reach it.
func (v *UnlockedVault) Decrypt() ([]byte, error) {
	b, err := os.ReadFile(v.Path())
	if err != nil {
		return nil, err
	}
	salt := v.Salt()
	if salt == "" {
		// A vault's key is derived from the salt in its filename, so there is
		// nothing to decrypt with. findVaults rejects such a file, so reaching
		// here means a Vault was built from a path directly.
		return nil, fmt.Errorf("vault %s has no salt in its filename", v.Name())
	}
	decrypted, err := crypto.Decrypt(b, v.password, salt)
	if err != nil {
		// CLEANUP (added 2026-08-13): vaults created with --password-file
		// before trailing newlines were trimmed may include the newline in
		// their password. Retry with it re-appended; saving re-encrypts with
		// the trimmed password. Removable once every such vault has been saved
		// at least once, which the warning below asks the user to do.
		for _, suffix := range []string{"\n", "\r\n"} {
			legacyPassword := append(append([]byte{}, v.password...), suffix...)
			decrypted, err = crypto.Decrypt(b, legacyPassword, salt)
			crypto.Wipe(legacyPassword)
			if err == nil {
				warnf("vault %s was encrypted with a password that ends in a newline. "+
					"It will be re-encrypted with the trimmed password the next time you save it.",
					v.Name())
				break
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt vault %s", v)
	}
	return decrypted, nil
}

// Write encrypts plaintext into the vault. The caller owns plaintext and is
// responsible for wiping it.
func (v *UnlockedVault) Write(plaintext []byte) error {
	ciphertext, err := crypto.Encrypt(plaintext, v.password, v.Salt())
	if err != nil {
		return fmt.Errorf("failed to encrypt secrets, so vault %s is unchanged", v)
	}

	// A vault being written for the first time has nothing to back up.
	if _, statErr := os.Stat(v.Path()); statErr == nil {
		if copyErr := fs.CopyFile(v.Path(), v.Path()+".bak"); copyErr != nil {
			warnf("failed to create backup for vault %s: %s", v.Name(), copyErr)
		}
	}

	// Remove leftover temporary files from previously interrupted writes.
	// Callers hold the vault's exclusive lock, so any matching file is stale.
	_ = removeTempFiles(v.Path())

	if err := fs.WriteFileAtomic(v.Path(), ciphertext, 0600); err != nil {
		if errors.Is(err, fs.ErrDirSync) {
			// The vault was written and renamed; only the durability-hardening
			// directory sync failed, so warn instead of failing the save.
			warnf("vault %s was saved but %s", v.Name(), err)
			return nil
		}
		return err
	}
	return nil
}

// Wipe wipes the vault's password from memory.
func (v *UnlockedVault) Wipe() {
	crypto.Wipe(v.password)
}

func (v *UnlockedVault) changePassword(p []byte) error {
	b, err := v.Decrypt()
	if err != nil {
		return err
	}
	defer crypto.Wipe(b)

	v.password = p
	return v.Write(b)
}
