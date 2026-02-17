package fs

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/andornaut/mrs/internal/config"
)

// IsExists returns true if the given path exists.
// IsExists returns an error if it cannot determine whether the path exists
func IsExists(p string) (bool, error) {
	if _, err := os.Stat(p); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("could not dermine whether path %s exists", p)
}

// IsNotExists returns true if the given path does not exist or it is not accessible
func IsNotExists(p string) bool {
	_, err := os.Stat(p)
	return os.IsNotExist(err)
}

// RemoveFile removes a file or exits with a fatal error
func RemoveFile(p string) {
	if err := os.Remove(p); err != nil {
		log.Fatalf("could not remove %s: %s", p, err)
	}
}

// RemoveTempDir removes config.TempDir or exits with a fatal error.
// This must be called via defer in main.go.
func RemoveTempDir() {
	if err := os.RemoveAll(config.TempDir); err != nil {
		log.Fatalf("SECURITY WARNING: a directory that contains secrets was not removed %s: %s\n", config.TempDir, err)
	}
}

// WriteTempFile writes the given content to a newly created temp file.
// The caller is responsible for removing the create file and/or directory.
func WriteTempFile(content string) (string, error) {
	f, err := ioutil.TempFile(config.TempDir, "")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		return "", err
	}
	return f.Name(), nil
}

// CopyFile copies a file from source to destination
func CopyFile(src, dst string) error {
	input, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(dst, input, 0600)
}
