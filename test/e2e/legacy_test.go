package e2e

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"

	"github.com/andornaut/mrs/internal/crypto"
)

// gcm builds the AEAD that a vault file is sealed with. Fixtures are built and
// read against crypto/aes directly rather than through mrs's own crypto
// package, so that they pin the file format rather than agreeing with whatever
// that package currently does.
func gcm(t *testing.T, password, salt string, iterations int) cipher.AEAD {
	t.Helper()
	k := pbkdf2.Key([]byte(password), []byte(salt), iterations, 32, sha256.New)
	block, err := aes.NewCipher(k)
	if err != nil {
		t.Fatalf("failed to build the fixture cipher: %s", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("failed to build the fixture cipher: %s", err)
	}
	return aead
}

// Capability 6: vault files written by earlier versions of mrs, which are
// upgraded in place, and the backup that is the way back from a save.
//
// The fixtures are written the way the version that made them would have,
// because current mrs cannot write an out-of-date vault at all. Every assertion
// is made against the real binary reading and writing them.

// encrypt returns ciphertext as a version of mrs deriving its key from the
// given salt and iteration count would have written it.
func encrypt(t *testing.T, plaintext, password, salt string, iterations int) []byte {
	t.Helper()
	aead := gcm(t, password, salt, iterations)
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("failed to encrypt the fixture: %s", err)
	}
	// The nonce is prefixed to the ciphertext, which is the layout mrs reads.
	return aead.Seal(nonce, nonce, []byte(plaintext), nil)
}

// decrypts reports whether a vault file can be decrypted with a key derived
// the given way, which is how these tests tell one key derivation from another
// through a file that mrs will read either way.
func decrypts(t *testing.T, path, password, salt string, iterations int) bool {
	t.Helper()
	aead := gcm(t, password, salt, iterations)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %s", path, err)
	}
	n := aead.NonceSize()
	if len(b) < n {
		return false
	}
	_, err = aead.Open(nil, b[:n], b[n:], nil)
	return err == nil
}

// writeVaultFile writes a vault file directly, as an older mrs would have left
// it, and returns its path.
func (l *lab) writeVaultFile(filename, password, contents, salt string, iterations int) string {
	l.t.Helper()
	if err := os.MkdirAll(l.VaultDir(), 0700); err != nil {
		l.t.Fatalf("failed to create %s: %s", l.VaultDir(), err)
	}
	p := filepath.Join(l.VaultDir(), filename)
	if err := os.WriteFile(p, encrypt(l.t, contents, password, salt, iterations), 0600); err != nil {
		l.t.Fatalf("failed to write %s: %s", p, err)
	}
	return p
}

func TestAVaultFileWithNoSaltIsReportedAndIgnored(t *testing.T) {
	l := newLab(t)
	// Versions before v0.0.3 derived every key from one static salt and left it
	// out of the filename. mrs derives a key from the salt a filename carries,
	// so such a file names no vault it can open.
	p := l.writeVaultFile("personal", "a password", "a key\na-value\n",
		"99daa49d-3a53-4bf8-a74a-93295de71d41-4bac-8cea", crypto.LegacyIterations)
	pwFile := l.PasswordFile("pw", "a password")

	// It is named on stderr, so that it cannot look as though the vault simply
	// vanished.
	l.Run("vault", "list").
		AssertOK().
		AssertStdoutEquals("").
		AssertStderr("ignoring").
		AssertStderr("personal")

	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertFailed().
		AssertStderr("not found")

	// The file itself is left alone, so it can still be recovered with an
	// older release.
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("expected the file to be left untouched: %s", err)
	}
}

func TestAVaultFileWithNoSaltDoesNotBlockANewVault(t *testing.T) {
	l := newLab(t)
	l.writeVaultFile("personal", "a password", "a key\na-value\n",
		"99daa49d-3a53-4bf8-a74a-93295de71d41-4bac-8cea", crypto.LegacyIterations)
	pwFile := l.PasswordFile("pw", "a password")

	// The old file is not a vault, so it does not occupy the name.
	l.Run("vault", "create", "personal", "-p", pwFile).AssertOK()
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")
}

func TestAVaultAtTheOldIterationCountIsUpgradedWhenItIsSaved(t *testing.T) {
	l := newLab(t)
	// A vault from the version that gave each vault its own salt but had not
	// yet raised the iteration count.
	salt := strings.Repeat("a", 32)
	p := l.writeVaultFile("personal."+salt, "a password", "a key\na-value\n", salt, crypto.LegacyIterations)
	pwFile := l.PasswordFile("pw", "a password")

	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\na-value\n").
		// Its filename already carries a salt, so there is nothing to say.
		AssertNoOutput("static salt")

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	// The salt is kept, since it is already unique; only the key derivation
	// is brought up to date.
	if filepath.Base(l.VaultPath("personal")) != "personal."+salt {
		t.Fatalf("expected the salt to be kept, got %q", l.VaultPath("personal"))
	}
	if !decrypts(t, p, "a password", salt, crypto.CurrentIterations) {
		t.Fatal("expected the saved vault to use the current iteration count")
	}
	if decrypts(t, p, "a password", salt, crypto.LegacyIterations) {
		t.Fatal("expected the saved vault to no longer use the old iteration count")
	}
}

func TestAnOldVaultKeepsItsSaltWhenRenamed(t *testing.T) {
	l := newLab(t)
	salt := strings.Repeat("c", 32)
	l.writeVaultFile("personal."+salt, "a password", "a key\nold-value\n", salt, crypto.LegacyIterations)
	pwFile := l.PasswordFile("pw", "a password")

	// Renaming does not decrypt, so the salt has to travel with the file.
	l.Run("vault", "rename", "personal", "archive").AssertOK()
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("archive")
	if got := filepath.Base(l.VaultPath("archive")); got != "archive."+salt {
		t.Fatalf("expected the salt to travel with the vault, got %q", got)
	}
	l.Run("export", "-v", "archive", "-p", pwFile).
		AssertOK().
		AssertStdout("old-value")

	l.Run("vault", "delete", "archive", "--yes").AssertOK()
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("")
	// Nothing that still holds the secrets may be left behind. Lock files are
	// left in place by every command and hold nothing, so they do not count.
	assertNoPlaintextUnder(t, l.VaultDir(), "old-value")
	for _, name := range l.Vaults() {
		if !strings.HasSuffix(name, ".lock") {
			t.Errorf("expected the deleted vault to leave only lock files, found %q", name)
		}
	}
}

func TestAPasswordThatEndsInANewlineIsStillAccepted(t *testing.T) {
	l := newLab(t)
	// Before trailing newlines were trimmed from a password file, `echo a
	// password > pw` encrypted the vault with the newline included.
	salt := strings.Repeat("b", 32)
	l.writeVaultFile("personal."+salt, "a password\n", "a key\na-value\n", salt, crypto.CurrentIterations)
	pwFile := l.PasswordFile("pw", "a password\n")

	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\na-value\n").
		AssertStderr("ends in a newline")

	// Saving re-encrypts with the trimmed password, so the notice stops.
	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()
	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertNoOutput("ends in a newline")
}

func TestTheBackupHoldsTheVersionBeforeTheSave(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\nfirst-value\n")
	vaultPath := l.VaultPath("personal")
	l.editorWrites("a key\nsecond-value\n")

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()
	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\nsecond-value\n")

	// Copying the backup over the vault is the documented way back from an
	// edit, so it has to decrypt and hold what was there before.
	copyFile(t, vaultPath+".bak", vaultPath)
	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\nfirst-value\n")
}

func TestTheBackupIsNotReadableByOthers(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na-value\n")
	l.editorAppends("b key\nb-value\n")

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	// A backup holds the same secrets as the vault, so it is guarded the same.
	assertFileMode(t, l.VaultPath("personal"), 0600)
	assertFileMode(t, l.VaultPath("personal")+".bak", 0600)
}

func TestALeftoverTemporaryFileIsRemovedOnSave(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na-value\n")
	vaultPath := l.VaultPath("personal")
	// A write that was interrupted between the temporary file and the rename
	// leaves one of these behind.
	stale := vaultPath + ".123456.tmp"
	if err := os.WriteFile(stale, []byte("stale"), 0600); err != nil {
		t.Fatalf("failed to write %s: %s", stale, err)
	}

	l.editorAppends("b key\nb-value\n")
	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	assertNotExists(t, stale)
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")
}

// copyFile copies a file, which is how a user restores a backup.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("failed to read %s: %s", src, err)
	}
	if err := os.WriteFile(dst, b, 0600); err != nil {
		t.Fatalf("failed to write %s: %s", dst, err)
	}
}
