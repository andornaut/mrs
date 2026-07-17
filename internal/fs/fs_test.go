package fs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsExists(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "exists")
	if err := os.WriteFile(f, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"File exists", f, true},
		{"File does not exist", filepath.Join(tmpDir, "nope"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsExists(tt.path)
			if err != nil {
				t.Fatalf("IsExists() error = %v", err)
			}
			if got != tt.expected {
				t.Errorf("IsExists() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestWriteTempFile(t *testing.T) {
	// Ensure config points to a test-specific temp dir
	tmpRoot := t.TempDir()
	t.Setenv("MRS_TEMP", tmpRoot)

	content := "secret data"
	path, err := WriteTempFile(content)
	if err != nil {
		t.Fatalf("WriteTempFile() error = %v", err)
	}
	defer func() { _ = RemoveFile(path) }()

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

func TestWriteFileAtomicPreservesMode(t *testing.T) {
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, "target")
	if err := os.WriteFile(p, []byte("old"), 0400); err != nil {
		t.Fatal(err)
	}

	if err := WriteFileAtomic(p, []byte("new"), 0600); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v", err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0400 {
		t.Errorf("permissions = %v, expected 0400 to be preserved", info.Mode().Perm())
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
