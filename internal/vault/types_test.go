package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	if err := Vault("").repairLock(); err == nil {
		t.Error("expected repairLock() on an unnamed vault to return an error")
	}
}

// Repairing keeps the lock file's identity, so that whatever holds it goes on
// holding it. Only a directory in its place, which nothing can be holding, is
// removed.
func TestRepairLock(t *testing.T) {
	v := newTestVault(t)

	// Nothing to repair is not an error: taking the lock creates the file.
	if err := v.repairLock(); err != nil {
		t.Errorf("repairLock() with no lock file should be nil, got: %v", err)
	}

	// A lock file that cannot be opened is made openable, and stays the same file.
	if err := os.WriteFile(v.lockPath(), []byte{}, 0600); err != nil {
		t.Fatalf("failed to create lock file: %v", err)
	}
	before, statErr := os.Stat(v.lockPath())
	if statErr != nil {
		t.Fatalf("failed to stat the lock file: %v", statErr)
	}
	if err := os.Chmod(v.lockPath(), 0); err != nil {
		t.Fatalf("failed to make the lock file unusable: %v", err)
	}
	if err := v.repairLock(); err != nil {
		t.Fatalf("repairLock() error: %v", err)
	}
	after, statErr := os.Stat(v.lockPath())
	if statErr != nil {
		t.Fatalf("expected the lock file to still be there: %v", statErr)
	}
	if after.Mode().Perm() != 0600 {
		t.Errorf("expected the repaired lock file to be mode 0600, got %v", after.Mode().Perm())
	}
	if !os.SameFile(before, after) {
		t.Error("expected repairLock() to keep the lock file, so that a holder goes on holding it")
	}

	// A directory in its place was never a lock, so it goes.
	if err := os.Remove(v.lockPath()); err != nil {
		t.Fatalf("failed to remove the lock file: %v", err)
	}
	if err := os.Mkdir(v.lockPath(), 0700); err != nil {
		t.Fatalf("failed to put a directory in place of the lock: %v", err)
	}
	if err := v.repairLock(); err != nil {
		t.Fatalf("repairLock() on a directory error: %v", err)
	}
	if _, err := os.Stat(v.lockPath()); !os.IsNotExist(err) {
		t.Errorf("expected the directory to be removed, stat err = %v", err)
	}
}

// --force repairs a lock that cannot be used. It never takes one another
// process holds: removing the lock file to do that would leave the two
// processes holding two different files, each believing the vault was theirs.
func TestExclusiveLockRepairDoesNotTakeAHeldLock(t *testing.T) {
	v := newTestVault(t)

	held, err := v.ExclusiveLock()
	if err != nil {
		t.Fatalf("ExclusiveLock() error: %v", err)
	}
	defer held()

	for _, repair := range []bool{false, true} {
		unlock, err := v.ExclusiveLockRepair(repair)
		if err == nil {
			unlock()
			t.Fatalf("ExclusiveLockRepair(%v) took a lock another process holds", repair)
		}
		if !errors.Is(err, ErrLockHeld) {
			t.Errorf("ExclusiveLockRepair(%v) = %v, want ErrLockHeld", repair, err)
		}
	}

	// Asking for a repair that cannot help says so, rather than repeating the
	// refusal it would have given anyway.
	if _, err := v.ExclusiveLockRepair(true); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("expected the refusal to say what --force does, got %v", err)
	}
}

// Whatever is left where the lock file should be, --force leaves a lock that
// can be taken. Where the platform refuses it outright, that is the whole point
// of the flag; where the platform can lock it anyway, the flag must not make
// things worse.
func TestExclusiveLockRepairFixesAnUnusableLockFile(t *testing.T) {
	for _, tt := range []struct {
		name string
		// mayLock reports that some platforms take a lock on what this leaves
		// behind rather than refusing it. Darwin locks a directory quite
		// happily; Linux will not open one for writing.
		mayLock bool
		break_  func(t *testing.T, path string)
	}{
		{name: "mode 0", break_: func(t *testing.T, p string) {
			t.Helper()
			if err := os.WriteFile(p, []byte{}, 0); err != nil {
				t.Fatalf("failed to write the lock file: %v", err)
			}
		}},
		{name: "a directory", mayLock: true, break_: func(t *testing.T, p string) {
			t.Helper()
			if err := os.Mkdir(p, 0700); err != nil {
				t.Fatalf("failed to create the directory: %v", err)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := newTestVault(t)
			tt.break_(t, v.lockPath())

			switch unlock, err := v.ExclusiveLockRepair(false); {
			case err == nil:
				// The platform locked what was there, so the vault is already
				// excluded and there is nothing to repair.
				unlock()
				if !tt.mayLock {
					t.Fatal("ExclusiveLockRepair(false) = <nil>, want ErrLockUnusable")
				}
			case !errors.Is(err, ErrLockUnusable):
				t.Fatalf("ExclusiveLockRepair(false) = %v, want ErrLockUnusable", err)
			}

			unlock, err := v.ExclusiveLockRepair(true)
			if err != nil {
				t.Fatalf("ExclusiveLockRepair(true) should leave a lockable lock, got: %v", err)
			}
			unlock()
		})
	}
}
