package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	// Avoid hidden files, paths with '../', names with file extensions, and names with special characters, etc.
	// Names cannot contain the "." character, because it is used as the name/salt separator.
	nameRegex = regexp.MustCompile(`^[\w-]+$`)
	// A salt is 32 base64url characters, as crypto.Salt() writes it.
	// Requiring its exact shape keeps unrelated files that a user
	// or another program left in the vault directory - notes.txt, README.md -
	// from being reported as vaults.
	saltRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)
)

// maxNameLen bounds a vault name so that its filename fits within the 255 byte
// limit that most filesystems impose. A name is followed by a "." separator, a
// 32 character salt, and suffixes of up to 20 characters such as ".lock" and
// ".<random>.tmp". Without this, a long name fails deep inside a lock or a
// write with an obscure "file name too long".
const maxNameLen = 200

// minPasswordLen is counted in characters rather than bytes, so that a
// passphrase written in a script whose characters take more than one byte is
// measured the way the person who wrote it would count it.
const minPasswordLen = 8

// ValidateName reports whether a name can be used for a vault.
func ValidateName(n string) error {
	if !nameRegex.MatchString(n) {
		return fmt.Errorf("invalid vault name %q", n)
	}
	if len(n) > maxNameLen {
		return fmt.Errorf("vault name must be at most %d characters, but is %d characters", maxNameLen, len(n))
	}
	return nil
}

func validateSalt(s string) error {
	if !saltRegex.MatchString(s) {
		return fmt.Errorf("invalid vault salt %q", s)
	}
	return nil
}

// validateFilename checks the shape of a vault's filename, <name>.<salt>. A
// vault's key is derived from the salt its filename carries, so a file without
// one is not a vault this version of mrs can open.
func validateFilename(n string) error {
	name, salt, hasSalt := strings.Cut(n, ".")
	if err := ValidateName(name); err != nil {
		return err
	}
	if !hasSalt {
		return fmt.Errorf("vault filename %q has no salt", n)
	}
	return validateSalt(salt)
}

// ValidateNewPassword is ValidatePassword, naming which of the two passwords
// a change asks for was refused, since the current one is asked for as well.
func ValidateNewPassword(p []byte) error {
	if err := ValidatePassword(p); err != nil {
		return fmt.Errorf("invalid new password: %w", err)
	}
	return nil
}

// ValidatePassword reports whether a password can be used for a vault. A
// command may call it to refuse early, as ValidateName is called, so that a
// password mrs will not accept is refused before anything else is asked for.
func ValidatePassword(p []byte) error {
	// A newline is refused rather than counted. readPasswordFile trims the one
	// an editor leaves at the end, so a password that still holds one came from
	// a file of several lines, which is nearly always a file of something other
	// than a password. Counting it would encrypt a vault under that file, and
	// reporting it as a length is what the character count below is for.
	if bytes.ContainsRune(p, '\n') {
		return errors.New("password cannot contain a newline")
	}
	if utf8.RuneCount(p) < minPasswordLen {
		return fmt.Errorf("password must contain at least %d characters", minPasswordLen)
	}
	return nil
}

// validatePath reports whether the entry at p, whose filename the caller has
// already validated, is a vault this version of mrs can read: what only a stat
// can answer. Its errors are phrased as reasons rather than as complete
// sentences, because callers report them as the reason a vault cannot be read.
func validatePath(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		// A path that is present as a symlink whose target is not, as when
		// the drive a vault lives on is not mounted, is not a vault that was
		// never there, so it is not answered with os.ErrNotExist.
		if errors.Is(err, os.ErrNotExist) {
			if _, lstatErr := os.Lstat(p); lstatErr == nil {
				return errors.New("a symlink whose target is not there")
			}
		}
		return err
	}
	if fi.IsDir() {
		return errors.New("a vault is a file, and this is a directory")
	}
	return nil
}
