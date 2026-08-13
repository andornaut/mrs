package e2e

import (
	"os"
	"strings"
	"testing"
)

// Capability 10: who can read a vault, and what mrs does when the filesystem
// refuses a write.

// requireUnprivileged skips a test that would prove nothing as root, since
// root is not stopped by the permission bits the test is about.
func requireUnprivileged(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root, which permission bits do not restrain")
	}
}

// chmod changes a path's mode or fails the test.
func chmod(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, mode); err != nil {
		t.Fatalf("failed to chmod %s: %s", p, err)
	}
}

func TestAVaultLoosenedByHandIsTightenedWhenItIsSaved(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")
	path := l.VaultPath("personal")

	// A umask, a restored archive or an rsync can leave a vault readable, or
	// writable, by everyone. Saving must not carry that forward.
	for _, loose := range []os.FileMode{0644, 0666, 0640, 0604} {
		chmod(t, path, loose)

		l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

		assertFileMode(t, path, 0600)
	}
	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\na value\n")
}

func TestAStricterVaultModeIsKept(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")
	path := l.VaultPath("personal")
	// A user who made their vault read-only meant it, and a save is a rename
	// over the file rather than a write to it, so it still works.
	chmod(t, path, 0400)

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	assertFileMode(t, path, 0400)
	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\na value\n")
}

func TestALoosenedBackupIsTightenedToo(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\nfirst-value\n")
	l.editorWrites("a key\nsecond-value\n")
	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()
	backup := l.VaultPath("personal") + ".bak"

	chmod(t, backup, 0644)
	l.editorWrites("a key\nthird-value\n")
	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	// A backup holds the same secrets as the vault, so it is guarded alike.
	assertFileMode(t, backup, 0600)
}

func TestTheVaultDirectoryIsTightenedWhenItIsLoose(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")
	// The filenames name the vaults, so a readable directory tells anyone on
	// the machine what is kept here even though the vaults are encrypted.
	chmod(t, l.VaultDir(), 0755)

	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")

	assertDirMode(t, l.VaultDir(), 0700)
}

func TestAReadOnlyVaultDirectoryFailsTheSaveAndKeepsTheVault(t *testing.T) {
	requireUnprivileged(t)
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\nthe-secret-value\n")
	path := l.VaultPath("personal")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read the vault: %s", err)
	}

	// A vault directory on a read-only mount, or one whose permissions were
	// changed underneath mrs. The save cannot happen, and must not damage
	// what is already there on its way to failing.
	chmod(t, l.VaultDir(), 0500)
	defer chmod(t, l.VaultDir(), 0700)

	l.editorWrites("a key\nreplacement\n")
	l.Run("edit", "-v", "personal", "-p", pwFile).
		AssertFailed().
		AssertStderr("permission denied")

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read the vault: %s", err)
	}
	if string(before) != string(after) {
		t.Fatal("expected a failed save to leave the vault untouched")
	}
	// No half-written file was left beside it either.
	for _, name := range l.Vaults() {
		if strings.HasSuffix(name, ".tmp") {
			t.Errorf("expected no temporary file after a failed save, found %q", name)
		}
	}

	chmod(t, l.VaultDir(), 0700)
	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\nthe-secret-value\n")
}

func TestAnUnreadableVaultIsReported(t *testing.T) {
	requireUnprivileged(t)
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\nthe-secret-value\n")
	path := l.VaultPath("personal")
	chmod(t, path, 0000)
	defer chmod(t, path, 0600)

	// Nothing can be decrypted, so say why rather than reporting a vault that
	// failed to decrypt, which would send the user looking for their password.
	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertFailed().
		AssertStderr("permission denied").
		AssertNoOutput("the-secret-value")
}
