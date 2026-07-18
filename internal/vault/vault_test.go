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
	err = u.Write("test content")
	if err != nil {
		t.Fatalf("failed to create test vault: %v", err)
	}

	// Create lock and backup files that should be excluded
	lockFile := filepath.Join(vaultDir, "test.lock")
	backupFile := filepath.Join(vaultDir, "test.12345678901234567890123456789012.bak")
	err = os.WriteFile(lockFile, []byte{}, 0600)
	if err != nil {
		t.Fatalf("failed to create lock file: %v", err)
	}
	err = os.WriteFile(backupFile, []byte{}, 0600)
	if err != nil {
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

func TestFindVaultsSkipsStrayFiles(t *testing.T) {
	config.Reset()
	tmpDir := t.TempDir()
	t.Setenv("MRS_HOME", tmpDir)

	vaultDir, err := config.GetVaultDir()
	if err != nil {
		t.Fatalf("failed to get vault dir: %v", err)
	}

	validVault := filepath.Join(vaultDir, "test.12345678901234567890123456789012")
	password := []byte("password")
	u := Vault(validVault).Unlocked(password)
	defer u.Wipe()
	if err = u.Write("test content"); err != nil {
		t.Fatalf("failed to create test vault: %v", err)
	}

	// Stray files that do not match the vault filename shape should be
	// skipped, not fail the whole listing
	for _, name := range []string{".DS_Store", ".test.swp", "notes.txt.orig"} {
		if err = os.WriteFile(filepath.Join(vaultDir, name), []byte{}, 0600); err != nil {
			t.Fatalf("failed to create stray file %s: %v", name, err)
		}
	}

	vaults, err := All()
	if err != nil {
		t.Fatalf("All() failed: %v", err)
	}
	if len(vaults) != 1 {
		t.Errorf("expected 1 vault, got %d", len(vaults))
	}
}

func TestNewReaderTrailingNewlinePasswordFallback(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "test.12345678901234567890123456789012")

	// Simulate a vault created before trailing newlines were trimmed from
	// password files: the newline is part of the encryption password.
	legacyPassword := []byte("password1\n")
	uLegacy := Vault(vaultPath).Unlocked(legacyPassword)
	if err := uLegacy.Write("secret content"); err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	// Unlocking with the trimmed password should succeed via the fallback
	u := Vault(vaultPath).Unlocked([]byte("password1"))
	defer u.Wipe()
	r, err := u.NewReader()
	if err != nil {
		t.Fatalf("NewReader() with trimmed password failed: %v", err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.Wipe(b)
	if string(b) != "secret content" {
		t.Errorf("content = %q, expected %q", string(b), "secret content")
	}
}

func TestDeleteRemovesCompanionFiles(t *testing.T) {
	config.Reset()
	tmpDir := t.TempDir()
	t.Setenv("MRS_HOME", tmpDir)

	vaultDir, err := config.GetVaultDir()
	if err != nil {
		t.Fatalf("failed to get vault dir: %v", err)
	}

	vaultPath := filepath.Join(vaultDir, "test.12345678901234567890123456789012")
	password := []byte("password")
	u := Vault(vaultPath).Unlocked(password)
	defer u.Wipe()
	if err = u.Write("first"); err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}
	if err = u.Write("second"); err != nil {
		t.Fatalf("failed to update vault: %v", err)
	}
	for _, name := range []string{"test.lock", "test.12345678901234567890123456789012.123.tmp"} {
		if err = os.WriteFile(filepath.Join(vaultDir, name), []byte{}, 0600); err != nil {
			t.Fatalf("failed to create companion file %s: %v", name, err)
		}
	}

	if err = Delete("test"); err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}

	// Delete removes the vault, its backup, and stale temporary files. The
	// lock file is intentionally left in place, like other commands.
	entries, err := os.ReadDir(vaultDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 1 || names[0] != "test.lock" {
		t.Errorf("expected only the lock file to remain after delete, got %v", names)
	}
}

func TestDeleteReportsBackupRemovalFailure(t *testing.T) {
	config.Reset()
	tmpDir := t.TempDir()
	t.Setenv("MRS_HOME", tmpDir)

	vaultDir, err := config.GetVaultDir()
	if err != nil {
		t.Fatalf("failed to get vault dir: %v", err)
	}

	vaultPath := filepath.Join(vaultDir, "test.12345678901234567890123456789012")
	password := []byte("password")
	u := Vault(vaultPath).Unlocked(password)
	defer u.Wipe()
	if err = u.Write("secret"); err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	// Make the backup path unremovable by making it a non-empty directory, so
	// os.Remove fails with a non-NotExist error.
	bakDir := vaultPath + ".bak"
	if err = os.Mkdir(bakDir, 0700); err != nil {
		t.Fatalf("failed to create backup dir: %v", err)
	}
	if err = os.WriteFile(filepath.Join(bakDir, "child"), []byte{}, 0600); err != nil {
		t.Fatalf("failed to populate backup dir: %v", err)
	}

	if err = Delete("test"); err == nil {
		t.Fatal("expected Delete() to return an error when the backup cannot be removed")
	}
	// The vault itself must still have been deleted.
	if _, statErr := os.Stat(vaultPath); !os.IsNotExist(statErr) {
		t.Errorf("expected vault file to be deleted, stat err = %v", statErr)
	}
}

func TestRenameReportsBackupMoveFailure(t *testing.T) {
	config.Reset()
	tmpDir := t.TempDir()
	t.Setenv("MRS_HOME", tmpDir)

	vaultDir, err := config.GetVaultDir()
	if err != nil {
		t.Fatalf("failed to get vault dir: %v", err)
	}

	salt := "12345678901234567890123456789012"
	sourcePath := filepath.Join(vaultDir, "src."+salt)
	password := []byte("password")
	u := Vault(sourcePath).Unlocked(password)
	defer u.Wipe()
	// Two writes so that a real backup exists at the source path.
	if err = u.Write("first"); err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}
	if err = u.Write("second"); err != nil {
		t.Fatalf("failed to update vault: %v", err)
	}

	// Renaming a file onto an existing directory fails with EISDIR, so a
	// directory at the target backup path makes the backup move fail.
	targetVaultPath := filepath.Join(vaultDir, "dst."+salt)
	if err = os.Mkdir(targetVaultPath+".bak", 0700); err != nil {
		t.Fatalf("failed to create target backup dir: %v", err)
	}

	if err = Rename("src", "dst"); err == nil {
		t.Fatal("expected Rename() to return an error when the backup cannot be moved")
	}
	// The vault itself must still have been renamed.
	if _, statErr := os.Stat(targetVaultPath); statErr != nil {
		t.Errorf("expected renamed vault at %q, stat err = %v", targetVaultPath, statErr)
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
