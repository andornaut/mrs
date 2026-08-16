package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// newTestVault returns a Vault rooted in a temp dir with name "test" and a salt.
func newTestVault(t *testing.T) Vault {
	t.Helper()
	return Vault(filepath.Join(t.TempDir(), "test."+testSalt))
}

func TestLockPath(t *testing.T) {
	v := newTestVault(t)
	want := filepath.Join(filepath.Dir(v.Path()), "test.lock")
	if got := v.lockPath(); got != want {
		t.Errorf("lockPath() = %q, want %q", got, want)
	}
}

func TestExclusiveLockAndUnlock(t *testing.T) {
	v := newTestVault(t)

	unlock, err := v.ExclusiveLock()
	if err != nil {
		t.Fatalf("ExclusiveLock() error: %v", err)
	}

	// Locking creates the lock file.
	if _, statErr := os.Stat(v.lockPath()); statErr != nil {
		t.Errorf("expected lock file at %q: %v", v.lockPath(), statErr)
	}

	// A second exclusive lock while the first is held must fail.
	if _, lockErr := v.ExclusiveLock(); lockErr == nil {
		t.Error("expected second ExclusiveLock() to fail while lock is held")
	}

	unlock()

	// After unlocking, a new exclusive lock must succeed.
	unlock2, err := v.ExclusiveLock()
	if err != nil {
		t.Fatalf("ExclusiveLock() after unlock error: %v", err)
	}
	unlock2()
}

// An unnamed vault has no lock path, so locking it would lock the vault
// directory itself.
func TestAnUnnamedVaultCannotBeLocked(t *testing.T) {
	if _, err := Vault("").ExclusiveLock(); err == nil {
		t.Error("expected ExclusiveLock() on an unnamed vault to return an error")
	}
	if err := Vault("").RemoveLock(); err == nil {
		t.Error("expected RemoveLock() on an unnamed vault to return an error")
	}
}

func TestRemoveLock(t *testing.T) {
	v := newTestVault(t)

	// Removing a lock file that is not there is a no-op, not an error.
	if err := v.RemoveLock(); err != nil {
		t.Errorf("RemoveLock() with no lock file should be nil, got: %v", err)
	}

	if err := os.WriteFile(v.lockPath(), []byte{}, 0600); err != nil {
		t.Fatalf("failed to create lock file: %v", err)
	}
	if err := v.RemoveLock(); err != nil {
		t.Fatalf("RemoveLock() error: %v", err)
	}
	if _, err := os.Stat(v.lockPath()); !os.IsNotExist(err) {
		t.Errorf("expected lock file to be deleted, stat err = %v", err)
	}
}

// With a lock held, force=false fails like ExclusiveLock, while force=true
// breaks it.
func TestExclusiveLockForce(t *testing.T) {
	v := newTestVault(t)

	held, err := v.ExclusiveLock()
	if err != nil {
		t.Fatalf("ExclusiveLock() error: %v", err)
	}
	defer held()

	// Without force, acquiring a held lock must fail.
	if _, lockErr := v.ExclusiveLockForce(false); lockErr == nil {
		t.Error("expected ExclusiveLockForce(false) to fail while lock is held")
	}

	// With force, the held lock is broken and acquisition succeeds.
	forced, err := v.ExclusiveLockForce(true)
	if err != nil {
		t.Fatalf("ExclusiveLockForce(true) should succeed, got: %v", err)
	}
	forced()
}
