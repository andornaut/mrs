package vault

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/andornaut/mrs/internal/config"
	"github.com/andornaut/mrs/internal/crypto"
	"github.com/andornaut/mrs/internal/fs"
)

func TestFindVaultsExcludesLockAndBackupFiles(t *testing.T) {
	config.Reset()
	tmpDir := t.TempDir()
	t.Setenv("MRS_HOME", tmpDir)

	// Get the vaults directory (this will create it)
	vaultDir, err := config.GetVaultDir()
	if err != nil {
		t.Fatalf("failed to get vault dir: %v", err)
	}

	// Create a valid vault
	validVault := filepath.Join(vaultDir, "test.12345678901234567890123456789012")
	password := []byte("password")
	u := Vault(validVault).Unlocked(password)
	defer u.Wipe()
	if err := u.Write("test content"); err != nil {
		t.Fatalf("failed to create test vault: %v", err)
	}

	// Create lock and backup files that should be excluded
	lockFile := filepath.Join(vaultDir, "test.lock")
	backupFile := filepath.Join(vaultDir, "test.12345678901234567890123456789012.bak")
	if err := os.WriteFile(lockFile, []byte{}, 0600); err != nil {
		t.Fatalf("failed to create lock file: %v", err)
	}
	if err := os.WriteFile(backupFile, []byte{}, 0600); err != nil {
		t.Fatalf("failed to create backup file: %v", err)
	}

	// Find all vaults - should only return the valid one
	vaults, err := All()
	if err != nil {
		t.Fatalf("All() failed: %v", err)
	}

	if len(vaults) != 1 {
		t.Errorf("expected 1 vault, got %d", len(vaults))
	}

	if len(vaults) > 0 && vaults[0].Name() != "test" {
		t.Errorf("expected vault name 'test', got %q", vaults[0].Name())
	}
}

func TestWriteBackup(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mrs-test-vault")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	vaultPath := filepath.Join(tmpDir, "test.12345678901234567890123456789012")
	password := []byte("password")
	u := Vault(vaultPath).Unlocked(password)
	defer u.Wipe()

	// First write should not create a backup
	err = u.Write("first content")
	if err != nil {
		t.Fatalf("first write failed: %v", err)
	}

	bakPath := vaultPath + ".bak"
	exists, err := fs.IsExists(bakPath)
	if err == nil && exists {
		t.Error("backup file should not exist after first write")
	}

	// Second write should create a backup
	err = u.Write("second content")
	if err != nil {
		t.Fatalf("second write failed: %v", err)
	}

	exists, err = fs.IsExists(bakPath)
	if err != nil || !exists {
		t.Error("backup file should exist after second write")
	}

	// Verify backup content
	vBak := Vault(bakPath).Unlocked(password)
	r, err := vBak.NewReader()
	if err != nil {
		t.Fatalf("failed to read backup: %v", err)
	}
	b, _ := io.ReadAll(r)
	defer crypto.Wipe(b)
	if string(b) != "first content" {
		t.Errorf("backup content mismatch; expected %q, got %q", "first content", string(b))
	}
}
