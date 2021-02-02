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
)

func validateName(n string) error {
	if !nameRegex.MatchString(n) {
		return fmt.Errorf("invalid vault name \"%s\"", n)
	}
	return nil
}

func validateNameWithOptionalSalt(n string) error {
	arr := strings.SplitN(n, ".", 2)
	err := validateName(arr[0])
	if err != nil {
		return err
	}
	if len(arr) == 1 {
		return nil
	}
	return validateName(arr[1])
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
	if err := validateNameWithOptionalSalt(fi.Name()); err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("vault path \"%s\" should be a file, but is a directory", p)
	}
	return nil
}
