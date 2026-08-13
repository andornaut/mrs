package e2e

import (
	"path/filepath"
	"strings"
	"testing"
)

// Capability 5: what two mrs processes do to one vault at the same time. The
// lock is a real file lock between real processes, so these tests hold one
// open in an editor session and run a second mrs against it.

// heldVault starts an editing session that sits in the editor holding the
// vault's lock, and returns a function that ends it. Every test here needs a
// lock that is genuinely held by another process, not merely a file on disk.
func (l *lab) heldVault(name, pwFile string) func() {
	l.t.Helper()
	ready := filepath.Join(filepath.Dir(l.Home), "lock-held-"+name)
	l.Setenv("FAKE_EDITOR_MODE", "hang")
	l.Setenv("FAKE_EDITOR_SLEEP", "60")
	l.Setenv("FAKE_EDITOR_READY", ready)

	cmd := l.Start("edit", "-v", name, "-p", pwFile)
	waitForFile(l.t, ready)

	// Later commands in the test are separate processes, so reset the editor
	// settings that only the held session needed.
	l.Setenv("FAKE_EDITOR_MODE", "noop")
	delete(l.Env, "FAKE_EDITOR_READY")
	delete(l.Env, "FAKE_EDITOR_SLEEP")

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

	// Both writers would read, edit and write the whole vault, so the second
	// one would silently discard the first one's work.
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
	l.RunStdin("y\n", "vault", "delete", "work").
		AssertFailed().
		AssertStderr("locked by another process")

	l.Run("vault", "rename", "work", "archive").
		AssertFailed().
		AssertStderr("locked by another process")

	// The vault is still there under its own name.
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("work")
}

func TestReadersAreNotBlockedWhileAVaultIsOpen(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\nthe-secret-value\n")
	release := l.heldVault("work", pwFile)
	defer release()

	// A write is atomic, so a reader sees either the old vault or the new one
	// and never a half-written file. Making readers wait would buy nothing.
	l.Run("export", "-v", "work", "-p", pwFile).
		AssertOK().
		AssertStdout("the-secret-value")

	l.Run("search", "-v", "work", "-p", pwFile, "a key").
		AssertOK().
		AssertStdout("the-secret-value")

	l.Run("vault", "list").AssertOK().AssertStdoutEquals("work")
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

func TestForceBreaksAHeldLock(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")
	release := l.heldVault("work", pwFile)
	defer release()

	// --force exists for a lock left behind by a process that died. It cannot
	// tell that case from a session that is still open, so it breaks both.
	l.editorAppends("forced key\nforced value\n")
	l.Run("edit", "--force", "-v", "work", "-p", pwFile).AssertOK()

	if got := l.export("work", pwFile); !strings.Contains(got, "forced value") {
		t.Fatalf("expected the forced edit to be saved, got %q", got)
	}
}

func TestCreateIsRefusedWhileTheNameIsHeldAndCanBeForced(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")
	release := l.heldVault("work", pwFile)
	defer release()

	// A name that is taken is refused for being taken, whether or not another
	// process holds its lock: the lock is transient and the collision is not,
	// so the collision is the more useful thing to say.
	newPw := l.PasswordFile("new.pw", "another password")
	for _, args := range [][]string{
		{"vault", "create", "work", "-p", newPw},
		{"vault", "create", "--force", "work", "-p", newPw},
	} {
		l.Run(args...).AssertFailed().AssertStderr("already exists")
	}

	// A free name creates normally once the lock is out of the way.
	l.Run("vault", "create", "--force", "other", "-p", newPw).AssertOK()
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

func TestALockFileIsNotMistakenForAVault(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")
	release := l.heldVault("work", pwFile)
	defer release()

	// While the lock is held there is a work.lock beside the vault file.
	var sawLock bool
	for _, name := range l.Vaults() {
		if name == "work.lock" {
			sawLock = true
		}
	}
	if !sawLock {
		t.Fatalf("expected a lock file while the vault is open, got %v", l.Vaults())
	}

	l.Run("vault", "list").AssertOK().AssertStdoutEquals("work")
	l.Run("vault", "default").AssertOK().AssertStdoutEquals("work")
}
