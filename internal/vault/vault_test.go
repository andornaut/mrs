package vault

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/andornaut/mrs/internal/fs"
)

func TestWriteBackup(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mrs-test-vault")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	vaultPath := filepath.Join(tmpDir, "test.12345678901234567890123456789012")
	password := "password"
	u := Vault(vaultPath).Unlocked(password)

	// First write should not create a backup
	err = u.Write("first content")
	if err != nil {
		t.Fatalf("first write failed: %v", err)
	}

	bakPath := vaultPath + ".bak"
	if exists, err := fs.IsExists(bakPath); err == nil && exists {
		t.Error("backup file should not exist after first write")
	}

	// Second write should create a backup
	err = u.Write("second content")
	if err != nil {
		t.Fatalf("second write failed: %v", err)
	}

	if exists, err := fs.IsExists(bakPath); err != nil || !exists {
		t.Error("backup file should exist after second write")
	}

	// Verify backup content
	vBak := Vault(bakPath).Unlocked(password)
	r, err := vBak.NewReader()
	if err != nil {
		t.Fatalf("failed to read backup: %v", err)
	}
	b, _ := io.ReadAll(r)
	if string(b) != "first content" {
		t.Errorf("backup content mismatch; expected %q, got %q", "first content", string(b))
	}
}
