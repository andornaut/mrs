package vault

import (
	"errors"
	"fmt"
	"os"
	"regexp"
)

var (
	// Avoid hidden files, paths with '../', names with file extensions, and names with special characters, etc.
	nameRegex     = regexp.MustCompile(`^[\w-_]+$`)
	passwordRegex = regexp.MustCompile(`^.{8,}$`) // TODO strengthen
)

func validateName(n string) error {
	if !nameRegex.MatchString(n) {
		return fmt.Errorf("invalid vault name \"%s\"", n)
	}
	return nil
}

func validatePassword(p string) error {
	if !passwordRegex.MatchString(p) {
		return errors.New("password must contain at least 8 characters")
	}
	return nil
}

func validatePath(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("invalid vault path \"%s\": %s", p, err)
	}
	if err := validateName(fi.Name()); err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("vault path \"%s\" should be a file, but is a directory", p)
	}
	if fi.Mode() != 0600 {
		return fmt.Errorf("vault file \"%s\" should have file mode %s, but has file mode %s", p, os.FileMode(0600), fi.Mode())
	}
	return nil
}
