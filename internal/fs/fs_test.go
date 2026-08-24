package fs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteTempFile(t *testing.T) {
	// Ensure config points to a test-specific temp dir
	tmpRoot := t.TempDir()
	t.Setenv("MRS_TEMP", tmpRoot)

	content := "secret data"
	path, err := WriteTempFile([]byte(content))
	if err != nil {
		t.Fatalf("WriteTempFile() error = %v", err)
	}
	defer func() { _ = os.Remove(path) }()

	// Verify content
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Errorf("WriteTempFile() content = %v, expected %v", string(got), content)
	}

	// Verify permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("WriteTempFile() permissions = %v, expected 0600", info.Mode().Perm())
	}
}

func TestWriteFileAtomic(t *testing.T) {
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, "target")

	if err := WriteFileAtomic(p, []byte("first"), 0600); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first" {
		t.Errorf("content = %q, expected %q", string(got), "first")
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("permissions = %v, expected 0600", info.Mode().Perm())
	}

	// No temporary files should be left behind
	matches, err := filepath.Glob(filepath.Join(tmpDir, "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Errorf("leftover temp files: %v", matches)
	}
}

// An existing file's mode is kept, but only as far as the owner's bits: a
// vault left readable by everyone would otherwise stay that way through every
// save, while a stricter mode the user chose is not undone by one.
func TestWriteFileAtomicMode(t *testing.T) {
	tests := []struct {
		before, want os.FileMode
	}{
		{0644, 0600},
		{0666, 0600},
		{0640, 0600},
		{0604, 0600},
		{0777, 0700},
		{0600, 0600},
		{0400, 0400},
	}
	for _, tt := range tests {
		tmpDir := t.TempDir()
		p := filepath.Join(tmpDir, "target")
		if err := os.WriteFile(p, []byte("old"), tt.before); err != nil {
			t.Fatal(err)
		}
		// os.WriteFile applies the umask, so set the mode explicitly.
		if err := os.Chmod(p, tt.before); err != nil {
			t.Fatal(err)
		}

		if err := WriteFileAtomic(p, []byte("new"), 0600); err != nil {
			t.Fatalf("WriteFileAtomic() error = %v", err)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != tt.want {
			t.Errorf("mode %04o became %04o, expected %04o", tt.before, info.Mode().Perm(), tt.want)
		}
	}
}

// A write that fails once the temporary file exists must not leave it behind.
// A stale ".tmp" beside a vault holds whatever was last written to it, and only
// the write that made it knows it is no longer wanted.
func TestAFailedWriteLeavesNoTemporaryFileBehind(t *testing.T) {
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, "target")
	// A directory where the file should be, so that the temporary file is
	// created and written and only the rename onto it fails.
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}

	if err := WriteFileAtomic(p, []byte("new"), 0600); err == nil {
		t.Fatal("expected WriteFileAtomic() to fail writing onto a directory")
	}

	matches, err := filepath.Glob(filepath.Join(tmpDir, "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Errorf("leftover temp files: %v", matches)
	}
}

// A parent directory that cannot be synced is not a failed write. The file was
// written and renamed and is already visible; only the hardening of that rename
// against power loss was missed, so the error wraps ErrDirSync and the callers
// that know a vault was written go on rather than reporting a failed save.
func TestAnUnsyncableParentDirectoryIsReportedAsErrDirSync(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which permission bits do not restrain")
	}
	dir := filepath.Join(t.TempDir(), "write-only")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	// Writable and enterable but not readable, so the temporary file is created
	// and renamed and only opening the directory to sync it fails.
	if err := os.Chmod(dir, 0300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	p := filepath.Join(dir, "target")
	err := WriteFileAtomic(p, []byte("new"), 0600)

	if !errors.Is(err, ErrDirSync) {
		t.Fatalf("WriteFileAtomic() = %v, want an error wrapping ErrDirSync", err)
	}
	// And what stopped the sync, so that the warning a caller prints says which
	// failure it was rather than only that there was one.
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("WriteFileAtomic() = %v, want it to name the permission failure", err)
	}
	got, readErr := os.ReadFile(p)
	if readErr != nil {
		t.Fatalf("expected the file to have been written anyway: %v", readErr)
	}
	if string(got) != "new" {
		t.Errorf("content = %q, expected %q", string(got), "new")
	}
}

func TestWriteFileAtomicWritesThroughSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "target")
	link := filepath.Join(tmpDir, "link")
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := WriteFileAtomic(link, []byte("new"), 0600); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v", err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink was replaced by a regular file")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("target content = %q, expected %q", string(got), "new")
	}
}

func TestCopyFile(t *testing.T) {
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "src")
	dst := filepath.Join(tmpDir, "dst")
	content := []byte("copy me")

	if err := os.WriteFile(src, content, 0600); err != nil {
		t.Fatal(err)
	}

	if err := CopyFile(src, dst); err != nil {
		t.Fatalf("CopyFile() error = %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Errorf("CopyFile() content = %v, expected %v", string(got), string(content))
	}
}
