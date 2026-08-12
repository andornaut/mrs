package e2e

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gtank/cryptopasta"
	"golang.org/x/crypto/pbkdf2"

	"github.com/andornaut/mrs/internal/crypto"
)

// Capability 6: vault files written by earlier versions of mrs, which are
// upgraded in place, and the backup that is the way back from a save.
//
// These tests build vault files the way the version that wrote them would
// have, rather than driving mrs to produce them, because current mrs cannot
// write a legacy vault at all. Only the fixtures are constructed; every
// assertion is made against the real binary reading and writing them.

// legacySalt is the one static salt that earlier versions of mrs derived every
// vault's key from. A vault file whose name carries no salt is still encrypted
// against it, so it is pinned here: changing it would strand every vault
// written before mrs gave each one its own salt.
const legacySalt = "99daa49d-3a53-4bf8-a74a-93295de71d41-4bac-8cea"

// encrypt returns ciphertext as a version of mrs deriving its key from the
// given salt and iteration count would have written it.
func encrypt(t *testing.T, plaintext, password, salt string, iterations int) []byte {
	t.Helper()
	var key [32]byte
	copy(key[:], pbkdf2.Key([]byte(password), []byte(salt), iterations, 32, sha256.New))
	b, err := cryptopasta.Encrypt([]byte(plaintext), &key)
	if err != nil {
		t.Fatalf("failed to encrypt the fixture: %s", err)
	}
	return b
}

// decrypts reports whether a vault file can be decrypted with a key derived
// the given way, which is how these tests tell one key derivation from another
// through a file that mrs will read either way.
func decrypts(t *testing.T, path, password, salt string, iterations int) bool {
	t.Helper()
	var key [32]byte
	copy(key[:], pbkdf2.Key([]byte(password), []byte(salt), iterations, 32, sha256.New))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %s", path, err)
	}
	_, err = cryptopasta.Decrypt(b, &key)
	return err == nil
}

// writeVaultFile writes a vault file directly, as an older mrs would have left
// it, and returns its path. A name without a salt is a legacy vault.
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

// writeLegacyVault writes a vault of the oldest shape: no salt in its name,
// the static salt, and the original iteration count.
func (l *lab) writeLegacyVault(name, password, contents string) string {
	l.t.Helper()
	return l.writeVaultFile(name, password, contents, legacySalt, crypto.LegacyIterations)
}

func TestALegacyVaultIsRead(t *testing.T) {
	l := newLab(t)
	l.writeLegacyVault("personal", "a password", "legacy key\nlegacy-value\n")
	pwFile := l.PasswordFile("pw", "a password")

	l.Run("vault", "export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("legacy key\nlegacy-value\n").
		// Reading is not enough to upgrade it, so say what will.
		AssertStderr("static salt")

	l.Run("search", "-v", "personal", "-p", pwFile, "legacy").
		AssertOK().
		AssertStdout("legacy-value")
}

func TestALegacyVaultIsListedLikeAnyOther(t *testing.T) {
	l := newLab(t)
	l.writeLegacyVault("personal", "a password", "legacy key\nlegacy-value\n")

	// A legacy filename carries no salt, so the check that keeps stray files
	// out of the listing must not mistake a legacy vault for one.
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal").AssertNoOutput("ignoring")
	l.Run("vault", "get-default").AssertOK().AssertStdoutEquals("personal")
}

func TestALegacyVaultIsUpgradedWhenItIsSaved(t *testing.T) {
	l := newLab(t)
	legacyPath := l.writeLegacyVault("personal", "a password", "legacy key\nlegacy-value\n")
	pwFile := l.PasswordFile("pw", "a password")
	l.editorAppends("new key\nnew-value\n")

	l.Run("edit", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStderr("Migrating legacy vault")

	// The file is renamed to carry its own salt, and the old one is gone.
	assertNotExists(t, legacyPath)
	upgraded := l.VaultPath("personal")
	salt := strings.TrimPrefix(filepath.Base(upgraded), "personal.")
	if len(salt) != 32 {
		t.Fatalf("expected a 32 character salt in %q, got %q", upgraded, salt)
	}

	got := l.export("personal", pwFile)
	for _, want := range []string{"legacy-value", "new-value"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected the upgraded vault to contain %q, got %q", want, got)
		}
	}
	// Reading it no longer warns, because there is nothing left to upgrade.
	l.Run("vault", "export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertNoOutput("static salt")
}

func TestAnUpgradedVaultUsesItsOwnSaltAndTheCurrentKeyDerivation(t *testing.T) {
	l := newLab(t)
	l.writeLegacyVault("personal", "a password", "legacy key\nlegacy-value\n")
	pwFile := l.PasswordFile("pw", "a password")

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	upgraded := l.VaultPath("personal")
	salt := strings.TrimPrefix(filepath.Base(upgraded), "personal.")
	if !decrypts(t, upgraded, "a password", salt, crypto.CurrentIterations) {
		t.Fatal("expected the upgraded vault to be encrypted with its own salt at the current iteration count")
	}
	// mrs falls back to the old iteration count when it reads, so a vault that
	// was merely renamed would still open. Check the ciphertext itself.
	if decrypts(t, upgraded, "a password", legacySalt, crypto.LegacyIterations) {
		t.Fatal("expected the upgraded vault to no longer be encrypted against the static salt")
	}
}

func TestAVaultAtTheOldIterationCountIsUpgradedWhenItIsSaved(t *testing.T) {
	l := newLab(t)
	// A vault from the version that gave each vault its own salt but had not
	// yet raised the iteration count.
	salt := strings.Repeat("a", 32)
	p := l.writeVaultFile("personal."+salt, "a password", "a key\na-value\n", salt, crypto.LegacyIterations)
	pwFile := l.PasswordFile("pw", "a password")

	l.Run("vault", "export", "-v", "personal", "-p", pwFile).
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

func TestALegacyVaultCanBeRenamedAndDeleted(t *testing.T) {
	l := newLab(t)
	l.writeLegacyVault("personal", "a password", "legacy key\nlegacy-value\n")
	pwFile := l.PasswordFile("pw", "a password")

	// Renaming does not decrypt, so a legacy vault stays legacy and keeps
	// working under its new name.
	l.Run("vault", "rename", "personal", "archive").AssertOK()
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("archive")
	l.Run("vault", "export", "-v", "archive", "-p", pwFile).
		AssertOK().
		AssertStdout("legacy-value")

	l.RunStdin("y\n", "vault", "delete", "-v", "archive").AssertOK()
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("")
	// Nothing that still holds the secrets may be left behind. Lock files are
	// left in place by every command and hold nothing, so they do not count.
	assertNoPlaintextUnder(t, l.VaultDir(), "legacy-value")
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

	l.Run("vault", "export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\na-value\n").
		AssertStderr("ends in a newline")

	// Saving re-encrypts with the trimmed password, so the notice stops.
	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()
	l.Run("vault", "export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertNoOutput("ends in a newline")
}

func TestTheBackupHoldsTheVersionBeforeTheSave(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\nfirst-value\n")
	vaultPath := l.VaultPath("personal")
	l.editorWrites("a key\nsecond-value\n")

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()
	l.Run("vault", "export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\nsecond-value\n")

	// Copying the backup over the vault is the documented way back from an
	// edit, so it has to decrypt and hold what was there before.
	copyFile(t, vaultPath+".bak", vaultPath)
	l.Run("vault", "export", "-v", "personal", "-p", pwFile).
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
