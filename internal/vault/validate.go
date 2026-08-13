package vault

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var (
	// Avoid hidden files, paths with '../', names with file extensions, and names with special characters, etc.
	// Names cannot contain the "." character, because it is used as the name/hash separator.
	nameRegex     = regexp.MustCompile(`^[\w-_]+$`)
	passwordRegex = regexp.MustCompile(`^.{8,}$`)
	// A salt is base64url encoded and truncated to a fixed length by
	// crypto.Salt(). Requiring its exact shape keeps unrelated files that a user
	// or another program left in the vault directory - notes.txt, README.md -
	// from being reported as vaults.
	saltRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)
)

// maxNameLen bounds a vault name so that its filename fits within the 255 byte
// limit that most filesystems impose. A name is followed by a "." separator, a
// 32 character salt, and suffixes of up to 20 characters such as ".bak" and
// ".<random>.tmp". Without this, a long name fails deep inside a lock or a
// write with an obscure "file name too long".
const maxNameLen = 200

func validateName(n string) error {
	if !nameRegex.MatchString(n) {
		return fmt.Errorf("invalid vault name \"%s\"", n)
	}
	if len(n) > maxNameLen {
		return fmt.Errorf("vault name must be at most %d characters, but is %d characters", maxNameLen, len(n))
	}
	return nil
}

func validateSalt(s string) error {
	if !saltRegex.MatchString(s) {
		return fmt.Errorf("invalid vault salt \"%s\"", s)
	}
	return nil
}

func validateNameWithOptionalSalt(n string) error {
	name, salt, hasSalt := strings.Cut(n, ".")
	if err := validateName(name); err != nil {
		return err
	}
	if !hasSalt {
		// Legacy vaults do not have a per-vault salt.
		return nil
	}
	return validateSalt(salt)
}

func validatePassword(p []byte) error {
	if !passwordRegex.Match(p) {
		return errors.New("password must contain at least 8 characters")
	}
	return nil
}

func validatePath(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("invalid vault path \"%s\": %w", p, err)
	}
	if err := validateNameWithOptionalSalt(fi.Name()); err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("vault path \"%s\" should be a file, but is a directory", p)
	}
	return nil
}
