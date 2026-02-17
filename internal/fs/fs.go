package fs

import (
	"fmt"
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
	return false, fmt.Errorf("could not determine whether path %s exists", p)
}

// IsNotExists returns true if the given path does not exist or it is not accessible
func IsNotExists(p string) bool {
	_, err := os.Stat(p)
	return os.IsNotExist(err)
}

// RemoveFile removes a file.
func RemoveFile(p string) error {
	return os.Remove(p)
}

// RemoveTempDir removes the temporary directory if it was created.
// This should be called via defer in main.go.
func RemoveTempDir() error {
	p, err := config.GetTempDir()
	if err != nil {
		return err
	}
	return os.RemoveAll(p)
}

// WriteTempFile writes the given content to a newly created temp file.
// The caller is responsible for removing the created file and/or directory.
func WriteTempFile(content string) (string, error) {
	tempDir, err := config.GetTempDir()
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(tempDir, "")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(content); err != nil {
		return "", err
	}
	return f.Name(), nil
}

// CopyFile copies a file from source to destination
func CopyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	return os.WriteFile(dst, input, 0600)
}
