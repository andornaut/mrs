package vault

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/andornaut/mrs/internal/crypto"
	"github.com/andornaut/mrs/internal/fs"
)

// Legacy vaults use the following salt, whereas new vaults are created with a unique salt.
// Legacy vaults are migrated when UnlockedVault.Write() is called.
const legacySalt = "99daa49d-3a53-4bf8-a74a-93295de71d41-4bac-8cea"

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
		salt = legacySalt
		fmt.Printf(
			"Vault \"%s\" uses a static salt. "+
				"It will be automatically upgraded to using a unique salt the next time you edit it.\n",
			v.Name())
	}
	decrypted, err := crypto.Decrypt(b, v.password, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt vault %s", v)
	}
	return bytes.NewReader(decrypted), nil
}

// Write writes s string to the vault
func (v *UnlockedVault) Write(s string) error {
	if err := v.migrateLegacyIfApplicable(); err != nil {
		return err
	}

	plaintext := []byte(s)
	defer crypto.Wipe(plaintext)

	ciphertext, err := crypto.Encrypt(plaintext, v.password, v.Salt())
	if err != nil {
		return fmt.Errorf("failed to encrypt secrets. Vault %s is unchanged", v)
	}

	if exists, err := fs.IsExists(v.Path()); err == nil && exists {
		if err := fs.CopyFile(v.Path(), v.Path()+".bak"); err != nil {
			fmt.Printf("Warning: failed to create backup for vault %s: %s\n", v.Name(), err)
		}
	}

	return os.WriteFile(v.Path(), ciphertext, 0600)
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

func (v *UnlockedVault) migrateLegacyIfApplicable() error {
	salt := v.Salt()
	if salt != "" {
		return nil
	}

	var err error
	if salt, err = crypto.Salt(); err != nil {
		return err
	}
	newPath, err := toPathWithSalt(v.Name(), salt)
	if err != nil {
		return err
	}
	newVault := Vault(newPath).Unlocked(v.password)
	if err := os.Rename(v.Path(), newVault.Path()); err != nil {
		return err
	}
	*v = newVault

	fmt.Printf("Migrating legacy vault to include a unique salt: %s\n", v.Salt())
	return nil
}
