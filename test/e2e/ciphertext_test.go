package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

// Capability 9: what the vault file gives away, and what it refuses. Every
// assertion is made against the bytes on disk or through mrs reading them back:
// these are the properties that hold when the file is in someone else's hands.

// tamper rewrites a vault file through a function, returning what was there.
func tamper(t *testing.T, path string, f func([]byte) []byte) []byte {
	t.Helper()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %s", path, err)
	}
	if err := os.WriteFile(path, f(append([]byte{}, before...)), 0600); err != nil {
		t.Fatalf("failed to write %s: %s", path, err)
	}
	return before
}

func TestTheVaultFileGivesAwayNothing(t *testing.T) {
	l := newLab(t)
	l.seedVault("personal", "a password",
		"my bank\naccount: 12345678\npin: 4321\n\nmy email\npassword: hunter2\n")

	b, err := os.ReadFile(l.VaultPath("personal"))
	if err != nil {
		t.Fatalf("failed to read the vault: %s", err)
	}
	// Neither the values nor the keys, which are what a search matches on and
	// would name what the vault holds even without the values.
	for _, secret := range []string{"12345678", "4321", "hunter2", "my bank", "my email", "a password"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("expected the vault file not to contain %q", secret)
		}
	}
}

func TestSavingTheSameSecretsTwiceWritesDifferentBytes(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")
	path := l.VaultPath("personal")

	// The editor changes nothing, so both saves encrypt identical plaintext
	// under the same key: the salt is in the filename and does not change.
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read the vault: %s", err)
	}
	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read the vault: %s", err)
	}

	// Identical bytes would mean the nonce was reused, which for AES-GCM
	// leaks the relationship between the two plaintexts.
	if bytes.Equal(first, second) {
		t.Fatal("expected each save to write different bytes")
	}
	if len(first) != len(second) {
		t.Fatalf("expected the same length for the same plaintext, got %d and %d", len(first), len(second))
	}
	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\na value\n")
}

func TestTwoVaultsWithTheSamePasswordAndSecretsDiffer(t *testing.T) {
	l := newLab(t)
	l.seedVault("first", "a password", "a key\na value\n")
	l.seedVault("second", "a password", "a key\na value\n")

	// Each vault gets its own salt, so the same password does not derive the
	// same key, and the two files cannot be told to hold the same secrets.
	a, err := os.ReadFile(l.VaultPath("first"))
	if err != nil {
		t.Fatalf("failed to read the vault: %s", err)
	}
	b, err := os.ReadFile(l.VaultPath("second"))
	if err != nil {
		t.Fatalf("failed to read the vault: %s", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("expected two vaults to differ despite holding the same secrets")
	}
}

func TestADamagedVaultIsRefusedRatherThanGuessedAt(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\nthe-secret-value\n")
	path := l.VaultPath("personal")

	damage := map[string]func([]byte) []byte{
		"one bit":      func(b []byte) []byte { b[len(b)/2] ^= 0x01; return b },
		"truncated":    func(b []byte) []byte { return b[:len(b)/2] },
		"emptied":      func(b []byte) []byte { return nil },
		"appended to":  func(b []byte) []byte { return append(b, 'x') },
		"overwritten":  func(b []byte) []byte { return bytes.Repeat([]byte{'x'}, len(b)) },
		"single byte":  func(b []byte) []byte { return []byte{'x'} },
		"first byte":   func(b []byte) []byte { b[0] ^= 0xff; return b },
		"last byte":    func(b []byte) []byte { b[len(b)-1] ^= 0xff; return b },
		"leading null": func(b []byte) []byte { return append([]byte{0}, b...) },
	}
	for name, f := range damage {
		before := tamper(t, path, f)

		// Every one of these has to be a clean refusal: mrs must never hand
		// back part of a secret, or something that looks like one.
		l.Run("export", "-v", "personal", "-p", pwFile).
			AssertFailed().
			AssertStderr("failed to decrypt").
			AssertNoOutput("the-secret-value")

		if err := os.WriteFile(path, before, 0600); err != nil {
			t.Fatalf("failed to restore the vault after %s: %s", name, err)
		}
	}

	// Restoring the bytes restores the vault, so none of the failed reads
	// altered the file on its way to refusing.
	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\nthe-secret-value\n")

	// Reading is one path whichever command asks for it, so one case stands
	// for the rest rather than deriving a key again per shape.
	tamper(t, path, damage["truncated"])
	l.Run("search", "-v", "personal", "-p", pwFile, "a key").
		AssertFailed().
		AssertStderr("failed to decrypt").
		AssertNoOutput("the-secret-value")
}

func TestATamperedBackupIsRefused(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\nfirst-value\n")
	l.editorWrites("a key\nsecond-value\n")
	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	backup := l.VaultPath("personal") + ".bak"
	tamper(t, backup, func(b []byte) []byte {
		b[len(b)/2] ^= 0x01
		return b
	})

	// A backup is restored by copying it over the vault, so it is protected
	// exactly as the vault is and fails the same way.
	copyFile(t, backup, l.VaultPath("personal"))
	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertFailed().
		AssertStderr("failed to decrypt").
		AssertNoOutput("first-value")
}

func TestAWrongPasswordRevealsNothingAboutTheSecrets(t *testing.T) {
	l := newLab(t)
	l.seedVault("personal", "a password", "my bank\npin: 4321\n")

	// A near miss and a wild guess are answered identically: nothing about the
	// secrets, and nothing about how close the password was.
	answers := make([]string, 0, 4)
	for _, guess := range []string{"a passwore", "a passwor", "a password ", "entirely different"} {
		r := l.Run("export", "-v", "personal", "-p", l.PasswordFile("guess.pw", guess)).
			AssertFailed().
			AssertNoOutput("4321").
			AssertNoOutput("my bank")
		answers = append(answers, r.Stderr)
	}
	for _, got := range answers[1:] {
		if got != answers[0] {
			t.Fatalf("expected every wrong password to be answered alike, got %q and %q", answers[0], got)
		}
	}
}

func TestAReaderNeverSeesAPartiallyWrittenVault(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\nthe-secret-value\n")
	// The environment is captured before the writer starts, so that nothing
	// touches the lab's map from two goroutines.
	env, dir := l.environ(), l.UserHome

	// A writer takes the vault's exclusive lock; a reader takes none, and
	// relies on the write being a rename over the old file. That is only
	// exercised when the two overlap, so the reader decides when to stop: the
	// writer keeps saving until enough reads have landed.
	const wantReads = 5
	var reads atomic.Int64
	stop := make(chan struct{})
	writes := make(chan error, 1)
	go func() {
		defer close(writes)
		var err error
		for reads.Load() < wantReads && err == nil {
			select {
			case <-stop:
				return
			default:
			}
			cmd := exec.Command(mrsBin, "edit", "-v", "personal", "-p", pwFile)
			cmd.Env, cmd.Dir = env, dir
			err = cmd.Run()
		}
		if err != nil {
			writes <- err
		}
	}()
	// A failed assertion below ends the test without reads reaching wantReads,
	// so the writer is stopped and waited for here rather than left saving into
	// a directory the test is about to remove.
	t.Cleanup(func() { close(stop); <-writes })

	for reads.Load() < wantReads {
		// Never a partial file, never a decryption failure, never an empty
		// vault: a reader sees the version before the save or the one after.
		l.Run("export", "-v", "personal", "-p", pwFile).
			AssertOK().
			AssertStdoutExactly("a key\nthe-secret-value\n")
		reads.Add(1)
	}
	if err := <-writes; err != nil {
		t.Fatalf("a write failed while reading: %s", err)
	}
}

func TestNoTemporaryFileIsLeftInTheVaultDirectory(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")
	l.editorAppends("b key\nb value\n")

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	// The write goes to a temporary file and is renamed over the vault, so
	// nothing of the sort may survive a save that succeeded.
	for _, name := range l.Vaults() {
		if strings.HasSuffix(name, ".tmp") {
			t.Errorf("expected no temporary file beside the vault, found %q", name)
		}
	}
}
