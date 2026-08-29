package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Capability 5: what two mrs processes do to one vault at the same time. The
// lock is a real file lock between real processes, so these tests hold one
// open in an editor session and run a second mrs against it.

// heldVault starts an editing session that sits in the editor holding the
// vault's lock, and returns a function that ends it. Every test here needs a
// lock genuinely held by another process, not merely a file on disk.
func (l *lab) heldVault(name, pwFile string) func() {
	l.t.Helper()
	ready := filepath.Join(filepath.Dir(l.Home), "lock-held-"+name)
	cmd := l.hangingEdit(ready, name, pwFile)

	// Later commands in the test are separate processes, so reset the editor
	// settings that only the held session needed.
	l.Setenv("FAKE_EDITOR_MODE", "noop")
	l.Unsetenv("FAKE_EDITOR_READY")
	l.Unsetenv("FAKE_EDITOR_SLEEP")

	return func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

func TestASecondWriterIsRefusedWhileAVaultIsOpen(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")
	release := l.heldVault("work", pwFile)
	defer release()

	// Both writers read, edit and write the whole vault, so the second would
	// silently discard the first one's work.
	for _, args := range [][]string{
		{"add", "-v", "work", "-p", pwFile},
		{"edit", "-v", "work", "-p", pwFile},
	} {
		l.Run(args...).
			AssertFailed().
			AssertStderr("locked by another process")
	}
}

func TestDeleteAndRenameAreRefusedWhileAVaultIsOpen(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")
	release := l.heldVault("work", pwFile)
	defer release()

	// Deleting is refused before the confirmation is asked, so answering "y"
	// cannot get past the lock.
	l.RunStdin("y\n", "vault", "rm", "work").
		AssertFailed().
		AssertStderr("locked by another process")

	l.Run("vault", "rename", "work", "archive").
		AssertFailed().
		AssertStderr("locked by another process")

	// The vault is still there under its own name.
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("work")
}

// The lock is taken before the password is asked for, so that nobody types a
// password for a vault another process is already writing. Run without
// --password-file and with a pipe for stdin, the two orders are told apart by
// which failure comes back: the lock, or the terminal that cannot be prompted on.
func TestTheLockIsTakenBeforeThePasswordIsAskedFor(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")
	release := l.heldVault("work", pwFile)
	defer release()

	for _, args := range [][]string{
		{"add", "-v", "work"},
		{"edit", "-v", "work"},
	} {
		l.RunStdin("a password\n", args...).
			AssertFailed().
			AssertStderr("locked by another process").
			AssertNoOutput("stdin is not a terminal")
	}
}

func TestReadersAreNotBlockedWhileAVaultIsOpen(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\nthe-secret-value\n")
	release := l.heldVault("work", pwFile)
	defer release()

	// A write is atomic, so a reader sees either the old vault or the new one
	// and never a half-written file.
	l.Run("export", "-v", "work", "-p", pwFile).
		AssertOK().
		AssertStdout("the-secret-value")

	l.Run("search", "-v", "work", "-p", pwFile, "a key").
		AssertOK().
		AssertStdout("the-secret-value")

	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("work")
}

func TestAnotherVaultIsUnaffectedByAHeldLock(t *testing.T) {
	l := newLab(t)
	workPw := l.seedVault("work", "a password", "a key\na value\n")
	homePw := l.seedVault("home", "a password", "b key\nb value\n")
	release := l.heldVault("work", workPw)
	defer release()

	// The lock covers one vault, not the whole vault directory.
	l.editorAppends("c key\nc value\n")
	l.Run("edit", "-v", "home", "-p", homePw).AssertOK()
	if got := l.export("home", homePw); !strings.Contains(got, "c value") {
		t.Fatalf("expected the edit to the other vault to be saved, got %q", got)
	}
}

func TestForceDoesNotTakeAHeldLock(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")
	release := l.heldVault("work", pwFile)
	defer release()

	// --force repairs a lock file that cannot be used. Taking one another
	// process holds would mean removing the file, leaving the two processes
	// holding two different files, so every command refuses it alike.
	l.editorAppends("forced key\nforced value\n")
	for _, args := range [][]string{
		{"add", "--force", "-v", "work", "-p", pwFile},
		{"edit", "--force", "-v", "work", "-p", pwFile},
		{"vault", "change-password", "--force", "work", "-p", pwFile, "-n", pwFile},
		{"vault", "rm", "--force", "work", "--yes"},
		{"vault", "rename", "--force", "work", "elsewhere"},
	} {
		l.Run(args...).
			AssertFailed().
			AssertStderr("locked by another process").
			// The refusal says why the flag did not help, rather than reading
			// as though it did nothing.
			AssertStderr("--force")
	}

	if got := l.export("work", pwFile); strings.Contains(got, "forced value") {
		t.Fatalf("expected no forced write to have landed, got %q", got)
	}
}

// A lock file that cannot be opened is the one thing --force is for: without it
// the vault cannot be locked at all, and no other command clears it.
func TestForceRepairsAnUnusableLockFile(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")
	lockPath := filepath.Join(l.VaultDir(), "work.lock")

	for _, tt := range []struct {
		name string
		// mayLock reports that some platforms take a lock on what this leaves
		// behind rather than refusing it. Darwin locks a directory quite
		// happily; Linux will not open one for writing.
		mayLock bool
		spoil   func(*testing.T)
	}{
		{name: "a lock file nothing may open", spoil: func(t *testing.T) {
			t.Helper()
			if err := os.WriteFile(lockPath, nil, 0); err != nil {
				t.Fatalf("failed to write the lock file: %s", err)
			}
		}},
		{name: "a directory in its place", mayLock: true, spoil: func(t *testing.T) {
			t.Helper()
			if err := os.Mkdir(lockPath, 0700); err != nil {
				t.Fatalf("failed to create the directory: %s", err)
			}
		}},
		// A symlink that does not resolve cannot be opened even to create what
		// it points at, and a chmod would follow it and fail on the target
		// exactly as the lock did, so the link is removed and the lock file
		// created afresh. A symlink whose target could be created is not this
		// case: taking the lock creates the target through the link and never
		// asks to repair.
		{name: "a symlink into a directory that is not there", spoil: func(t *testing.T) {
			t.Helper()
			if err := os.Symlink(filepath.Join(l.VaultDir(), "gone", "lock"), lockPath); err != nil {
				t.Fatalf("failed to create the symlink: %s", err)
			}
		}},
		{name: "a symlink that loops", spoil: func(t *testing.T) {
			t.Helper()
			if err := os.Symlink("work.lock", lockPath); err != nil {
				t.Fatalf("failed to create the symlink: %s", err)
			}
		}},
		// mayLock, because root enters a directory whose mode forbids everyone
		// else, and so reaches the target and locks it.
		{name: "a symlink into a directory nothing may enter", mayLock: true, spoil: func(t *testing.T) {
			t.Helper()
			shut := filepath.Join(l.VaultDir(), "shut")
			if err := os.Mkdir(shut, 0700); err != nil {
				t.Fatalf("failed to create the directory: %s", err)
			}
			if err := os.WriteFile(filepath.Join(shut, "lock"), nil, 0600); err != nil {
				t.Fatalf("failed to write the target: %s", err)
			}
			if err := os.Chmod(shut, 0); err != nil {
				t.Fatalf("failed to shut the directory: %s", err)
			}
			t.Cleanup(func() { _ = os.Chmod(shut, 0700) })
			if err := os.Symlink(filepath.Join(shut, "lock"), lockPath); err != nil {
				t.Fatalf("failed to create the symlink: %s", err)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_ = os.RemoveAll(lockPath)
			tt.spoil(t)

			l.editorAppends("")
			// Where the platform can lock what was left behind, the vault is
			// already excluded and there is nothing for --force to repair.
			if r := l.with(t).Run("edit", "-v", "work", "-p", pwFile); r.ExitCode == 0 {
				if !tt.mayLock {
					t.Fatalf("expected the save to be refused\n%s", r.describe())
				}
			} else {
				r.AssertStderr("lock file cannot be used")
			}
			l.with(t).Run("edit", "--force", "-v", "work", "-p", pwFile).AssertOK()
		})
	}
}

func TestCreateIsRefusedWhileTheNameIsHeld(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")
	release := l.heldVault("work", pwFile)
	defer release()

	// A name that is taken is refused for being taken, whether or not another
	// process holds its lock: the lock is transient and the collision is not.
	newPw := l.PasswordFile("new.pw", "another password")
	l.Run("vault", "add", "work", "-p", newPw).
		AssertFailed().
		AssertStderr("already exists")

	// --force means the same thing here as everywhere: repair a lock file that
	// cannot be used, never take one. A name that is taken stays taken.
	l.Run("vault", "add", "--force", "work", "-p", newPw).
		AssertFailed().
		AssertStderr("already exists")

	// A free name creates normally while another vault's lock is held.
	l.Run("vault", "add", "other", "-p", newPw).AssertOK()
}

func TestAReleasedLockDoesNotBlockLaterWrites(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")

	release := l.heldVault("work", pwFile)
	release()

	// Killing the holder leaves the lock file on disk. The file is not the
	// lock, so the next writer takes it without needing --force.
	l.editorAppends("b key\nb value\n")
	l.Run("edit", "-v", "work", "-p", pwFile).AssertOK()
	if got := l.export("work", pwFile); !strings.Contains(got, "b value") {
		t.Fatalf("expected the later edit to be saved, got %q", got)
	}
}
