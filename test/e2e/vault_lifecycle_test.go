package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Capability 1: the vault lifecycle — create, list, get-default, rename and
// delete — driven entirely through the CLI against a real vault directory.

func TestCreateVaultWritesAnEncryptedFile(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "correct horse battery staple")

	l.Run("vault", "create", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdout("Created vault personal")

	p := l.VaultPath("personal")
	if base := filepath.Base(p); !strings.HasPrefix(base, "personal.") {
		t.Fatalf("expected the vault file to be named personal.<salt>, got %q", base)
	}
	if salt := strings.TrimPrefix(filepath.Base(p), "personal."); len(salt) != 32 {
		t.Fatalf("expected a 32 character salt in the filename, got %q", salt)
	}
	assertFileMode(t, p, 0600)
	assertFileMode(t, l.VaultDir(), 0700)
}

func TestCreateVaultIsReportedByList(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")
	l.createVault("work", "a password")

	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal\nwork")
}

func TestListIsEmptyWhenNoVaultsExist(t *testing.T) {
	l := newLab(t)
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("")
}

func TestListPathsPrintsAbsolutePaths(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	r := l.Run("vault", "list", "--path").AssertOK()
	if got := strings.TrimSpace(r.Stdout); got != l.VaultPath("personal") {
		t.Fatalf("expected the vault path %q, got %q", l.VaultPath("personal"), got)
	}
	l.Run("vault", "list", "-p").AssertOK().AssertStdout(l.VaultDir())
}

func TestCreateRejectsADuplicateName(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")

	l.Run("vault", "create", "-v", "personal", "-p", pwFile).
		AssertFailed().
		AssertOutput("already exists")

	if names := l.Vaults(); len(names) != 2 { // the vault and its lock file
		t.Fatalf("expected the failed create to leave no extra files, found %v", names)
	}
}

func TestCreateRejectsInvalidNames(t *testing.T) {
	invalid := map[string]string{
		"a dot":            "my.vault",
		"a slash":          "my/vault",
		"a parent path":    "../escape",
		"an absolute path": "/etc/passwd",
		"a space":          "my vault",
		"a leading dot":    ".hidden",
		"an empty name":    "",
		"a tilde":          "~",
		"a wildcard":       "*",
	}
	for desc, name := range invalid {
		t.Run(desc, func(t *testing.T) {
			l := newLab(t)
			pwFile := l.PasswordFile("pw", "a password")

			r := l.Run("vault", "create", "-v", name, "-p", pwFile)
			r.AssertFailed()
			if names := l.Vaults(); len(names) != 0 {
				t.Fatalf("expected no files to be created for name %q, found %v\n%s", name, names, r.describe())
			}
		})
	}
}

func TestCreateRejectsAShortPassword(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "short")

	l.Run("vault", "create", "-v", "personal", "-p", pwFile).
		AssertFailed().
		AssertOutput("at least 8 characters")

	if names := l.Vaults(); len(names) != 0 {
		t.Fatalf("expected no vault to be created, found %v", names)
	}
}

func TestCreateReportsAMissingPasswordFile(t *testing.T) {
	l := newLab(t)

	l.Run("vault", "create", "-v", "personal", "-p", filepath.Join(l.UserHome, "absent")).
		AssertFailed().
		AssertOutput("could not read from password file")
}

func TestCreatePromptsForTheVaultName(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	l.RunStdin("personal\n", "vault", "create", "-p", pwFile).
		AssertOK().
		AssertStdout("Created vault personal")
}

func TestGetDefaultPrintsTheOnlyVault(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	l.Run("vault", "get-default").AssertOK().AssertStdoutEquals("personal")
	l.Run("vault", "get-default", "--path").AssertOK().AssertStdoutEquals(l.VaultPath("personal"))
}

func TestGetDefaultIsEmptyWhenNoVaultsExist(t *testing.T) {
	l := newLab(t)
	l.Run("vault", "get-default").AssertOK().AssertStdoutEquals("")
}

func TestGetDefaultHonoursTheConfiguredName(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")
	l.createVault("work", "a password")

	l.Setenv("MRS_DEFAULT_VAULT_NAME", "work")
	l.Run("vault", "get-default").AssertOK().AssertStdoutEquals("work")
}

func TestGetDefaultFailsWhenTheConfiguredVaultIsMissing(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	l.Setenv("MRS_DEFAULT_VAULT_NAME", "absent")
	l.Run("vault", "get-default").
		AssertFailed().
		AssertOutput(`default vault "absent" not found`)
}

func TestListIgnoresStrayFiles(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	// Files that other tools leave behind in a data directory.
	for _, name := range []string{".DS_Store", "README.md", ".personal.swp", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(l.VaultDir(), name), []byte("x"), 0600); err != nil {
			t.Fatalf("failed to write %s: %s", name, err)
		}
	}
	r := l.Run("vault", "list").AssertOK()
	r.AssertStdoutEquals("personal")
	// Visible files are reported, so that a vault file renamed by hand does not
	// vanish silently. Hidden files are never vaults, so they stay quiet.
	r.AssertStderr("README.md")
	r.AssertStderr("notes.txt")
	if strings.Contains(r.Stderr, "DS_Store") || strings.Contains(r.Stderr, "swp") {
		t.Fatalf("expected hidden files to be skipped quietly\n%s", r.describe())
	}
}

func TestListWarnsAboutAVaultFileRenamedByHand(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")
	renamed := filepath.Join(l.VaultDir(), "personal.backup")
	if err := os.Rename(l.VaultPath("personal"), renamed); err != nil {
		t.Fatalf("failed to rename the vault file: %s", err)
	}

	l.Run("vault", "list").
		AssertOK().
		AssertStdoutEquals("").
		AssertStderr("personal.backup")
}

func TestListIgnoresLockBackupAndTempFiles(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")
	// Provoke a real backup by writing to the vault a second time.
	l.Setenv("FAKE_EDITOR_MODE", "append")
	l.Setenv("FAKE_EDITOR_CONTENT", "a key\na value\n")
	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	vaultPath := l.VaultPath("personal")
	if _, err := os.Stat(vaultPath + ".bak"); err != nil {
		t.Fatalf("expected a backup file next to the vault: %s", err)
	}
	// A leftover temporary file from an interrupted write.
	if err := os.WriteFile(vaultPath+".1234.tmp", []byte("x"), 0600); err != nil {
		t.Fatalf("failed to write temp file: %s", err)
	}
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")
}

func TestRenamePreservesTheSecrets(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")

	l.Run("vault", "rename", "personal", "renamed").
		AssertOK().
		AssertStdout("Renamed vault personal to renamed")

	l.Run("vault", "list").AssertOK().AssertStdoutEquals("renamed")
	if got := l.export("renamed", pwFile); !strings.Contains(got, "a value") {
		t.Fatalf("expected the renamed vault to keep its secrets, got %q", got)
	}
}

func TestRenameRejectsAnExistingTargetName(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")
	l.createVault("work", "a password")

	l.Run("vault", "rename", "personal", "work").
		AssertFailed().
		AssertOutput("already exists")
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal\nwork")
}

func TestRenameRejectsAnInvalidTargetName(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	l.Run("vault", "rename", "personal", "../escape").
		AssertFailed().
		AssertOutput("invalid vault name")
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")
}

func TestRenameRejectsIdenticalNames(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	l.Run("vault", "rename", "personal", "personal").AssertFailed()
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")
}

func TestRenameRequiresAnExactSourceName(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	l.Run("vault", "rename", "pers", "renamed").
		AssertFailed().
		AssertOutput(`Did you mean "personal"`)
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")
}

func TestRenameReportsAMissingVault(t *testing.T) {
	l := newLab(t)

	l.Run("vault", "rename", "absent", "renamed").
		AssertFailed().
		AssertOutput("not found")
}

func TestRenameMovesTheBackupFile(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")
	l.Setenv("FAKE_EDITOR_MODE", "append")
	l.Setenv("FAKE_EDITOR_CONTENT", "a key\na value\n")
	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	oldBackup := l.VaultPath("personal") + ".bak"
	if _, err := os.Stat(oldBackup); err != nil {
		t.Fatalf("expected a backup to exist before the rename: %s", err)
	}

	l.Run("vault", "rename", "personal", "renamed").AssertOK()

	assertNotExists(t, oldBackup)
	if _, err := os.Stat(l.VaultPath("renamed") + ".bak"); err != nil {
		t.Fatalf("expected the backup to move with the vault: %s", err)
	}
}

func TestDeleteRemovesTheVaultWhenConfirmed(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")
	vaultPath := l.VaultPath("personal")

	l.RunStdin("y\n", "vault", "delete", "-v", "personal").
		AssertOK().
		AssertStdout("Deleted vault personal")

	assertNotExists(t, vaultPath)
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("")
}

func TestDeleteKeepsTheVaultWhenDeclined(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	// Declining is a normal outcome, so it succeeds rather than erroring.
	l.RunStdin("n\n", "vault", "delete", "-v", "personal").
		AssertOK().
		AssertStdout("Cancelled")

	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")
}

func TestDeleteDefaultsToKeepingTheVault(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	// A bare newline accepts the default, which must not be destructive.
	l.RunStdin("\n", "vault", "delete", "-v", "personal").AssertOK().AssertStdout("Cancelled")
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")

	// So must reaching end-of-input without answering at all.
	l.RunStdin("", "vault", "delete", "-v", "personal").AssertOK()
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")
}

func TestDeleteRemovesTheBackupFile(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")
	l.Setenv("FAKE_EDITOR_MODE", "append")
	l.Setenv("FAKE_EDITOR_CONTENT", "a key\na value\n")
	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	backup := l.VaultPath("personal") + ".bak"
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("expected a backup to exist before the delete: %s", err)
	}

	l.RunStdin("y\n", "vault", "delete", "-v", "personal").AssertOK()

	assertNotExists(t, backup)
}

func TestDeleteRequiresAnExactName(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	l.RunStdin("y\n", "vault", "delete", "-v", "pers").
		AssertFailed().
		AssertOutput(`Did you mean "personal"`)
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")
}

func TestDeleteReportsAMissingVault(t *testing.T) {
	l := newLab(t)

	l.RunStdin("y\n", "vault", "delete", "-v", "absent").
		AssertFailed().
		AssertOutput("not found")
}

func TestVaultNamePrefixSelectsTheFirstMatch(t *testing.T) {
	l := newLab(t)
	l.seedVault("alpha", "a password", "alpha key\nalpha value\n")
	l.seedVault("alphabet", "a password", "alphabet key\nalphabet value\n")

	// A prefix that matches several vaults picks the first in sorted order.
	pwFile := l.PasswordFile("alpha.pw", "a password")
	l.Run("vault", "export", "-v", "alpha", "-p", pwFile).
		AssertOK().
		AssertStdout("alpha value").
		AssertNoOutput("alphabet value")
}

func TestVaultNamesAreCaseSensitive(t *testing.T) {
	l := newLab(t)
	l.seedVault("Personal", "a password", "upper key\nupper value\n")
	l.seedVault("personal", "a password", "lower key\nlower value\n")

	l.Run("vault", "list").AssertOK().AssertStdoutEquals("Personal\npersonal")
	pwFile := l.PasswordFile("Personal.pw", "a password")
	l.Run("vault", "export", "-v", "Personal", "-p", pwFile).
		AssertOK().
		AssertStdout("upper value").
		AssertNoOutput("lower value")
}

func TestCreateRejectsANonASCIIName(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	l.Run("vault", "create", "-v", "café", "-p", pwFile).
		AssertFailed().
		AssertOutput("invalid vault name")
}

func TestUnusableHomeIsReported(t *testing.T) {
	l := newLab(t)
	// A user who points MRS_HOME at a file should get a clear error, not a panic
	// or a silent empty listing.
	notADir := l.WriteFile("not-a-dir", "")
	l.Setenv("MRS_HOME", notADir)

	l.Run("vault", "list").AssertFailed().AssertOutput("not a directory")
}

func TestHelpDocumentsEveryCommand(t *testing.T) {
	l := newLab(t)

	root := l.Run("help").AssertOK()
	for _, c := range []string{"add", "edit", "search", "vault"} {
		root.AssertStdout(c)
	}
	vaultHelp := l.Run("help", "vault").AssertOK()
	for _, c := range []string{"change-password", "create", "delete", "export", "get-default", "list", "rename"} {
		vaultHelp.AssertStdout(c)
	}
}

func TestUnknownCommandFails(t *testing.T) {
	l := newLab(t)
	l.Run("nonsense").AssertFailed().AssertOutput("unknown command")
	l.Run("vault", "nonsense").AssertFailed().AssertOutput("unknown command")
}
