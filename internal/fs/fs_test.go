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
	defer RemoveFile(path)

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
