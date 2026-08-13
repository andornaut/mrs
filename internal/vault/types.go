package vault

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofrs/flock"

	"github.com/andornaut/mrs/internal/crypto"
	"github.com/andornaut/mrs/internal/fs"
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
	// basename must contain 0 or 1 "." characters.
	return strings.SplitN(v.basename(), ".", 2)[0]
}

// Salt returns a salt derived from the filename or empty string if one does not exist.
func (v Vault) Salt() string {
	if v == BadVault {
		return ""
	}
	// basename must contain 0 or 1 "." characters.
	arr := strings.SplitN(v.basename(), ".", 2)
	if len(arr) == 1 {
		return ""
	}
	return strings.TrimSuffix(arr[1], ".bak")
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

// ExclusiveLock acquires an exclusive lock on the vault.
// It returns an unlock function and any error encountered.
func (v Vault) ExclusiveLock() (func(), error) {
	if v == BadVault {
		return nil, fmt.Errorf("cannot lock bad vault")
	}
	f := flock.New(v.lockPath())
	locked, err := f.TryLock()
	if err != nil {
		return nil, fmt.Errorf("could not acquire lock on vault %s: %w", v.Name(), err)
	}
	if !locked {
		return nil, fmt.Errorf("vault %s is currently locked by another process", v.Name())
	}
	return func() { _ = f.Unlock() }, nil
}

// ExclusiveLockForce is like ExclusiveLock, but when force is true it first
// deletes the vault's lock file, breaking any lock held by another process.
func (v Vault) ExclusiveLockForce(force bool) (func(), error) {
	if force {
		if err := v.RemoveLock(); err != nil {
			return nil, err
		}
	}
	return v.ExclusiveLock()
}

// RemoveLock deletes the vault's lock file, breaking any lock held by another process.
func (v Vault) RemoveLock() error {
	if v == BadVault {
		return fmt.Errorf("cannot remove lock on bad vault")
	}
	if err := os.Remove(v.lockPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("could not remove lock on vault %s: %w", v.Name(), err)
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

// IsBad returns true if the vault is invalid.
func (v UnlockedVault) IsBad() bool {
	return v.Vault == BadVault
}

// NewReader returns an reader that reads vault content.
// The caller is responsible for wiping the returned content if they convert it to a mutable buffer.
func (v *UnlockedVault) NewReader() (io.Reader, error) {
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
		// Vaults created with --password-file before trailing newlines were
		// trimmed may include the newline in their password. Retry with it
		// re-appended. Saving re-encrypts with the trimmed password.
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
	return bytes.NewReader(decrypted), nil
}

// Write writes s string to the vault
func (v *UnlockedVault) Write(s string) error {
	plaintext := []byte(s)
	defer crypto.Wipe(plaintext)

	ciphertext, err := crypto.Encrypt(plaintext, v.password, v.Salt())
	if err != nil {
		return fmt.Errorf("failed to encrypt secrets, so vault %s is unchanged", v)
	}

	if exists, existsErr := fs.IsExists(v.Path()); existsErr == nil && exists {
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
	r, err := v.NewReader()
	if err != nil {
		return err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	defer crypto.Wipe(b)

	v.password = p
	return v.Write(string(b))
}
