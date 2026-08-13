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
		AssertStderr("Created vault personal")

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

	// --path has no short form, so that -p means the password file on every
	// command that takes one.
	for _, args := range [][]string{
		{"vault", "list", "-p"},
		{"vault", "get-default", "-p"},
	} {
		l.Run(args...).AssertFailed().AssertStderr("unknown shorthand flag")
	}
}

func TestCreateRejectsADuplicateName(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")

	l.Run("vault", "create", "-v", "personal", "-p", pwFile).
		AssertFailed().
		AssertStderr("already exists")

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
		AssertStderr("at least 8 characters")

	if names := l.Vaults(); len(names) != 0 {
		t.Fatalf("expected no vault to be created, found %v", names)
	}
}

func TestCreateReportsAMissingPasswordFile(t *testing.T) {
	l := newLab(t)

	l.Run("vault", "create", "-v", "personal", "-p", filepath.Join(l.UserHome, "absent")).
		AssertFailed().
		AssertStderr("could not read from password file")
}

// A create that cannot succeed says so before asking for a password, as delete
// resolves its vault before asking whether to delete it.
func TestCreateChecksWhatItCanBeforeAskingForAPassword(t *testing.T) {
	l := newLab(t)

	// No --password-file, so reaching the password prompt at all would fail
	// with "stdin is not a terminal" and never name the real problem.
	l.Run("vault", "create", "-v", "bad name").
		AssertFailed().
		AssertStderr(`invalid vault name "bad name"`).
		AssertNoOutput("terminal")

	l.Run("vault", "create", "-v", "personal", "-i", filepath.Join(l.UserHome, "absent")).
		AssertFailed().
		AssertStderr("could not read from import file").
		AssertNoOutput("terminal")

	if names := l.Vaults(); len(names) != 0 {
		t.Fatalf("expected no files to be created, found %v", names)
	}

	// A name already taken is the same case: the create cannot succeed, so
	// there is no reason to make the user type a password for it first.
	l.createVault("personal", "a password")
	l.Run("vault", "create", "-v", "personal").
		AssertFailed().
		AssertStderr(`a vault named "personal" already exists`).
		AssertNoOutput("terminal")
}

func TestCreatePromptsForTheVaultName(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	l.RunStdin("personal\n", "vault", "create", "-p", pwFile).
		AssertOK().
		AssertStderr("Created vault personal")
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
		AssertStderr(`default vault "absent" not found`)
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
		AssertStderr("Renamed vault personal to renamed")

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
		AssertStderr("already exists")
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal\nwork")
}

func TestRenameRejectsAnInvalidTargetName(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	l.Run("vault", "rename", "personal", "../escape").
		AssertFailed().
		AssertStderr("invalid vault name")
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
		AssertStderr(`Did you mean "personal"`)
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")
}

func TestRenameReportsAMissingVault(t *testing.T) {
	l := newLab(t)

	l.Run("vault", "rename", "absent", "renamed").
		AssertFailed().
		AssertStderr("not found")
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

	l.Run("vault", "delete", "-v", "personal", "--yes").
		AssertOK().
		AssertStderr("Deleted vault personal")

	assertNotExists(t, vaultPath)
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("")
}

// A pipe cannot answer a question, whatever it holds. Taking the safe answer
// and exiting 0 would tell the script that ran it that the delete was done, so
// mrs refuses instead and names the flag that answers in advance.
func TestDeleteWithoutAnAnswerKeepsTheVault(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	for _, stdin := range []string{"y\n", "n\n", "\n", ""} {
		l.RunStdin(stdin, "vault", "delete", "-v", "personal").
			AssertFailed().
			AssertStderr("stdin is not a terminal").
			AssertStderr("Use --yes")
		l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")
	}

	// And --yes answers it.
	l.Run("vault", "delete", "-v", "personal", "--yes").AssertOK().AssertStderr("Deleted vault personal")
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("")
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

	l.Run("vault", "delete", "-v", "personal", "--yes").AssertOK()

	assertNotExists(t, backup)
}

func TestDeleteRequiresAnExactName(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	// The name is checked before anything is asked, so the user is never made
	// to confirm deleting something that is not a vault.
	l.RunStdin("y\n", "vault", "delete", "-v", "pers").
		AssertFailed().
		AssertStderr(`Did you mean "personal"`).
		AssertNoOutput("(y/n)")
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")
}

func TestDeleteConfirmsWithTheVaultsOwnName(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	// A destructive confirmation has to name what will actually be destroyed,
	// whether it is asked or reported as unanswerable.
	l.RunStdin("n\n", "vault", "delete", "-v", "personal").
		AssertFailed().
		AssertStderr("Delete vault personal?")
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")
}

// Reading a vault takes a name prefix; changing one takes the whole name, so
// that a prefix cannot reach a vault the user did not name.
func TestReadingTakesAPrefixAndChangingTakesTheWholeName(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")

	// Reads.
	l.Run("search", "-v", "pers", "-p", pwFile, "a key").AssertOK().AssertStdout("a value")
	l.Run("vault", "export", "-v", "pers", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\na value\n")

	// Changes.
	newPw := l.PasswordFile("new.pw", "a different password")
	for _, args := range [][]string{
		{"vault", "change-password", "-v", "pers", "-p", pwFile, "-n", newPw},
		{"vault", "rename", "pers", "renamed"},
		{"vault", "delete", "-v", "pers"},
	} {
		l.RunStdin("y\n", args...).
			AssertFailed().
			AssertStderr(`Did you mean "personal"`)
	}

	// Nothing was changed by any of them.
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")
	l.Run("vault", "export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\na value\n")
}

func TestTheVaultFlagSaysWhichNameItTakes(t *testing.T) {
	l := newLab(t)

	// The flag cannot show the difference, so the help text has to.
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"search"}, "or the start of one"},
		{[]string{"vault", "export"}, "or the start of one"},
		{[]string{"add"}, "or the start of exactly one"},
		{[]string{"edit"}, "or the start of exactly one"},
		{[]string{"vault", "change-password"}, "full name of a vault"},
		{[]string{"vault", "delete"}, "full name of a vault"},
	} {
		l.Run(append(c.args, "--help")...).AssertOK().AssertStdout(c.want)
	}
}

func TestRenameChecksTheSourceNameBeforeLocking(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")

	// A rename that cannot happen must not lock the vault on its way to
	// failing, or the next command would need --force.
	l.Run("vault", "rename", "pers", "renamed").AssertFailed()

	l.editorAppends("a key\na value\n")
	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()
}

func TestDeleteReportsAMissingVault(t *testing.T) {
	l := newLab(t)

	l.RunStdin("y\n", "vault", "delete", "-v", "absent").
		AssertFailed().
		AssertStderr("not found")
}

// A prefix that names no vault exactly picks the first in alphabetical order.
// What keeps that safe is that the choice is never invisible: a prefix that
// could have meant more than one vault says which it took, the vault written to
// is named in the report, a prefix cannot reach a command that destroys or
// re-keys a vault, and an exact name always wins.
func TestAPrefixSelectsTheFirstMatchAndSaysWhich(t *testing.T) {
	l := newLab(t)
	l.seedVault("alpha", "a password", "alpha key\nalpha value\n")
	l.seedVault("alphabet", "a password", "alphabet key\nalphabet value\n")
	pwFile := l.PasswordFile("alpha.pw", "a password")

	l.Run("search", "-v", "alph", "-p", pwFile, "key").
		AssertOK().
		AssertStderr(`"alph" begins the name of 2 vaults, so vault alpha was chosen`).
		AssertStderr("in vault alpha\n").
		AssertStdout("alpha value").
		AssertNoOutput("alphabet value")

	// export writes nothing but secrets, so without the warning its choice
	// would be invisible: the same command with the same arguments returns a
	// different vault's secrets once a longer name exists beside the one meant.
	l.Run("vault", "export", "-v", "alph", "-p", pwFile).
		AssertOK().
		AssertStderr(`begins the name of 2 vaults`).
		AssertStdoutExactly("alpha key\nalpha value\n")

	// An exact name is not ambiguous, whatever else begins with it.
	l.Run("vault", "export", "-v", "alpha", "-p", pwFile).
		AssertOK().
		AssertNoOutput("begins the name of").
		AssertStdoutExactly("alpha key\nalpha value\n")

	// Nor is a prefix that reaches only one vault.
	l.Run("vault", "export", "-v", "alphab", "-p", pwFile).
		AssertOK().
		AssertNoOutput("begins the name of").
		AssertStdoutExactly("alphabet key\nalphabet value\n")

	// A command that refuses a prefix outright says so once, rather than
	// warning about a vault it is about to refuse to touch.
	l.RunStdin("y\n", "vault", "delete", "-v", "alph").
		AssertFailed().
		AssertStderr(`Did you mean "alpha"?`).
		AssertNoOutput("begins the name of")

	// add and edit take a prefix too, but refuse an ambiguous one rather than
	// choosing: reading the wrong vault shows the user something unexpected,
	// while writing to it leaves a secret where they will not look for it.
	l.editorAppends("added key\nadded value\n")
	for _, c := range []string{"add", "edit"} {
		l.Run(c, "-v", "alph", "-p", pwFile).
			AssertFailed().
			AssertStderr(`"alph" begins the name of 2 vaults: alpha, alphabet`).
			AssertStderr("Use the whole name")
	}

	// A prefix that reaches one vault is not ambiguous, so it still writes.
	l.Run("add", "-v", "alphab", "-p", pwFile).
		AssertOK().
		AssertStderr("added to vault alphabet\n")
}

// A vault is found by a glob on its name, so a shorter name is matched
// alongside every longer one beginning with it. Only "-" sorts before the "."
// that separates a name from its salt, so "work-archive" is the case that
// displaced "work" in the glob's order and shadowed it everywhere.
func TestAnExactNameIsNeverShadowedByALongerOne(t *testing.T) {
	l := newLab(t)
	workPw := l.seedVault("work", "a password", "k\nwork-value\n")
	l.seedVault("work-archive", "a password", "k\narchive-value\n")

	// Reading commands must read the vault that was named, not its neighbour.
	l.Run("vault", "export", "-v", "work", "-p", workPw).
		AssertOK().
		AssertStdoutExactly("k\nwork-value\n")
	l.Run("search", "-v", "work", "-p", workPw, "k").
		AssertOK().
		AssertStdout("work-value").
		AssertNoOutput("archive-value")

	// And writing commands must write to it. Saving to the wrong vault is the
	// same defect, but silent: only the vault named in the success message
	// would have told the user.
	l.editorAppends("added key\nadded-value\n")
	l.Run("add", "-v", "work", "-p", workPw).
		AssertOK().
		AssertStderr("added to vault work").
		AssertNoOutput("work-archive")

	archivePw := l.PasswordFile("archive.pw", "a password")
	if got := l.export("work-archive", archivePw); strings.Contains(got, "added-value") {
		t.Fatalf("expected the neighbouring vault to be untouched, got %q", got)
	}
}

func TestAnExactNameIsReachableByEveryCommand(t *testing.T) {
	l := newLab(t)
	workPw := l.seedVault("work", "a password", "k\nwork-value\n")
	l.seedVault("work-archive", "a password", "k\narchive-value\n")

	// rename, delete and change-password each require an exact name, and so
	// each reported "work" as missing while it sat behind "work-archive".
	newPw := l.PasswordFile("new.pw", "a different password")
	l.Run("vault", "change-password", "-v", "work", "-p", workPw, "-n", newPw).
		AssertOK().
		AssertStderr("Changed password of vault work")

	l.Run("vault", "rename", "work", "current").AssertOK()
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("current\nwork-archive")

	l.Run("vault", "delete", "-v", "work-archive", "--yes").AssertOK()
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("current")
	l.Run("vault", "export", "-v", "current", "-p", newPw).
		AssertOK().
		AssertStdoutExactly("k\nwork-value\n")
}

func TestTheDefaultVaultNameIsNotShadowedEither(t *testing.T) {
	l := newLab(t)
	workPw := l.seedVault("work", "a password", "k\nwork-value\n")
	l.seedVault("work-archive", "a password", "k\narchive-value\n")
	l.Setenv("MRS_DEFAULT_VAULT_NAME", "work")

	l.Run("vault", "get-default").AssertOK().AssertStdoutEquals("work")
	l.Run("search", "-p", workPw, "k").
		AssertOK().
		AssertStdout("work-value").
		AssertNoOutput("archive-value")
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
		AssertStderr("invalid vault name")
}

func TestUnusableHomeIsReported(t *testing.T) {
	l := newLab(t)
	// A user who points MRS_HOME at a file should get a clear error, not a panic
	// or a silent empty listing.
	notADir := l.WriteFile("not-a-dir", "")
	l.Setenv("MRS_HOME", notADir)

	l.Run("vault", "list").AssertFailed().AssertStderr("not a directory")
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
	l.Run("nonsense").AssertFailed().AssertStderr("unknown command")
	l.Run("vault", "nonsense").AssertFailed().AssertStderr("unknown command")
}

// A command that has no subcommands cannot have been given one, so an argument
// it does not take is reported as what it is. `mrs add "my key"` is a user
// expecting to name a secret, and "unknown command" answers a question they did
// not ask.
func TestACommandThatTakesNoArgumentsSaysSo(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")

	for _, args := range [][]string{
		{"add", "-p", pwFile, "my key"},
		{"edit", "-p", pwFile, "my key"},
		{"vault", "export", "-p", pwFile, "personal"},
		{"vault", "list", "personal"},
	} {
		l.Run(args...).
			AssertFailed().
			AssertStderr("takes no arguments").
			AssertNoOutput("unknown command")
	}

	// But a mistyped subcommand of `mrs vault` still is an unknown command.
	l.Run("vault", "lst").AssertFailed().AssertStderr("unknown command")
}

// Without a vault there is nothing to name, so asking which one to use has no
// answer a user could give. The first thing a new user runs is likely to be one
// of these, so it has to point at the command that gets them started.
func TestTheFirstRunSaysThereAreNoVaults(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	for _, args := range [][]string{
		{"add", "-p", pwFile},
		{"edit", "-p", pwFile},
		{"search", "-p", pwFile, "anything"},
		{"vault", "export", "-p", pwFile},
	} {
		l.Run(args...).
			AssertFailed().
			AssertStderr("no vaults found").
			AssertStderr("mrs vault create").
			AssertNoOutput("Vault name:")
	}
}

func TestVersionIsReported(t *testing.T) {
	l := newLab(t)

	// A binary installed from a release archive has to be able to say what it
	// is, so that a bug report can name a version. GoReleaser sets this at
	// link time; a build made any other way says "dev".
	l.Run("--version").AssertOK().AssertStdout("mrs version")

	// Not -v. Cobra gives --version that shorthand unless the flag is already
	// registered, and -v is --vault on every command under mrs.
	l.Run("-v").AssertFailed().AssertStderr("unknown shorthand flag")
	l.Run("help").AssertOK().AssertNoOutput("-v, --version")
}
