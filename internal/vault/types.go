package vault

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/andornaut/mrs/internal/crypto"
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
func (v Vault) Unlocked(password string) UnlockedVault {
	return UnlockedVault{v, password}
}

func (v Vault) basename() string {
	return filepath.Base(v.Path())
}

func (v Vault) dir() string {
	return filepath.Dir(v.Path())
}

// UnlockedVault is a vault that can be read from and written to
type UnlockedVault struct {
	Vault
	password string
}

// NewReader returns an reader that reads vault content
func (v *UnlockedVault) NewReader() (io.Reader, error) {
	b, err := ioutil.ReadFile(v.Path())
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
	b, err = crypto.Decrypt(b, v.password, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt vault %s", v)
	}
	return bytes.NewReader(b), nil
}

// Write writes s string to the vault
func (v *UnlockedVault) Write(s string) error {
	v.migrateLegacyIfApplicable()

	b := []byte(s)
	b, err := crypto.Encrypt(b, v.password, v.Salt())
	if err != nil {
		return fmt.Errorf("failed to encrypt secrets. Vault %s is unchanged", v)
	}

	return ioutil.WriteFile(v.Path(), b, 0600)
}

func (v *UnlockedVault) changePassword(p string) error {
	r, err := v.NewReader()
	if err != nil {
		return err
	}
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}
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
	newPath := toPathWithSalt(v.Name(), salt)
	newVault := Vault(newPath).Unlocked(v.password)
	os.Rename(v.Path(), newVault.Path())
	*v = newVault

	fmt.Printf("Migrating legacy vault to include a unique salt: %s\n", v.Salt())
	return nil
}
