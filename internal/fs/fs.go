package fs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/andornaut/mrs/internal/config"
)

// ErrDirSync reports that WriteFileAtomic wrote and renamed the file
// successfully but could not fsync the parent directory. The file's content is
// durable; only the rename's durability across power loss is not guaranteed.
// Callers may treat this as a warning rather than a failed write.
var ErrDirSync = errors.New("the parent directory could not be synced")

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

	// The copied content is durable even if only the parent directory could not
	// be synced, so treat ErrDirSync as success.
	if err := WriteFileAtomic(dst, input, 0600); err != nil && !errors.Is(err, ErrDirSync) {
		return err
	}
	return nil
}

// WriteFileAtomic writes data to the file at path p by writing to a temporary
// file in the same directory and renaming it into place, so that a crash or
// full disk cannot leave a truncated file. If p is a symlink, the write goes
// through to its target. An existing file's permissions are preserved;
// otherwise defaultPerm is used. The parent directory is synced afterwards so
// that the rename survives power loss; if only that sync fails, the file is
// durably written and the returned error wraps ErrDirSync so callers can treat
// it as a warning rather than a failed write.
func WriteFileAtomic(p string, data []byte, defaultPerm os.FileMode) (err error) {
	// Resolve symlinks so that the rename replaces the target, not the link.
	if target, evalErr := filepath.EvalSymlinks(p); evalErr == nil {
		p = target
	}
	perm := defaultPerm
	if fi, statErr := os.Stat(p); statErr == nil {
		perm = fi.Mode().Perm()
	}

	f, err := os.CreateTemp(filepath.Dir(p), filepath.Base(p)+".*.tmp")
	if err != nil {
		return err
	}
	tempPath := f.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = f.Close()
			_ = os.Remove(tempPath)
		}
	}()

	if err = f.Chmod(perm); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tempPath, p); err != nil {
		return err
	}
	renamed = true
	// The rename has already made the new content visible. Syncing the parent
	// directory only hardens the rename against power loss, so a failure is
	// returned wrapped in ErrDirSync for the caller to treat as a warning rather
	// than a failed write.
	if syncErr := syncDir(filepath.Dir(p)); syncErr != nil {
		return fmt.Errorf("%w: %w", ErrDirSync, syncErr)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
