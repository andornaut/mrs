package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Capability 1: the vault lifecycle (create, list, get-default, rename and
// delete), driven entirely through the CLI against a real vault directory.

func TestCreateVaultWritesAnEncryptedFile(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "correct horse battery staple")

	l.Run("vault", "add", "personal", "-p", pwFile).
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

	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("personal\nwork")
}

func TestListIsEmptyWhenNoVaultsExist(t *testing.T) {
	l := newLab(t)
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("")
}

func TestListPathsPrintsAbsolutePaths(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	r := l.Run("vault", "ls", "--path").AssertOK()
	if got := strings.TrimSpace(r.Stdout); got != l.VaultPath("personal") {
		t.Fatalf("expected the vault path %q, got %q", l.VaultPath("personal"), got)
	}

	// --path has no short form, so that -p means the password file on every
	// command that takes one.
	for _, args := range [][]string{
		{"vault", "ls", "-p"},
		{"vault", "default", "-p"},
	} {
		l.Run(args...).AssertFailed().AssertStderr("unknown shorthand flag")
	}
}

func TestCreateRejectsADuplicateName(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")

	l.Run("vault", "add", "personal", "-p", pwFile).
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
		"a non-ASCII name": "café",
	}
	for desc, name := range invalid {
		t.Run(desc, func(t *testing.T) {
			l := newLab(t)
			pwFile := l.PasswordFile("pw", "a password")

			r := l.Run("vault", "add", name, "-p", pwFile)
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

	l.Run("vault", "add", "personal", "-p", pwFile).
		AssertFailed().
		AssertStderr("at least 8 characters")

	if names := l.Vaults(); len(names) != 0 {
		t.Fatalf("expected no vault to be created, found %v", names)
	}
}

func TestCreateReportsAMissingPasswordFile(t *testing.T) {
	l := newLab(t)

	l.Run("vault", "add", "personal", "-p", filepath.Join(l.UserHome, "absent")).
		AssertFailed().
		AssertStderr("could not read from password file")
}

func TestCreateRejectsALongName(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	l.Run("vault", "add", strings.Repeat("a", 201), "-p", pwFile).
		AssertFailed().
		AssertStderr("at most 200 characters")

	// A name that fits is still accepted.
	l.Run("vault", "add", strings.Repeat("a", 200), "-p", pwFile).AssertOK()
}

// A create that cannot succeed says so before asking for a password, as delete
// resolves its vault before asking whether to delete it.
func TestCreateChecksWhatItCanBeforeAskingForAPassword(t *testing.T) {
	l := newLab(t)

	// No --password-file, so reaching the password prompt at all would fail
	// with "stdin is not a terminal" and never name the real problem.
	l.Run("vault", "add", "bad name").
		AssertFailed().
		AssertStderr(`invalid vault name "bad name"`).
		AssertNoOutput("terminal")

	l.Run("vault", "add", "personal", "-i", filepath.Join(l.UserHome, "absent")).
		AssertFailed().
		AssertStderr("could not read from import file").
		AssertNoOutput("terminal")

	if names := l.Vaults(); len(names) != 0 {
		t.Fatalf("expected no files to be created, found %v", names)
	}

	// A name already taken is the same case: the create cannot succeed, so
	// there is no reason to make the user type a password for it first.
	l.createVault("personal", "a password")
	l.Run("vault", "add", "personal").
		AssertFailed().
		AssertStderr(`a vault named "personal" already exists`).
		AssertNoOutput("terminal")
}

// A vault a command creates, changes or removes is named by an operand, so a
// missing name is a wrong invocation rather than a prompt.
func TestCreateRequiresAName(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	l.Run("vault", "add", "-p", pwFile).
		AssertUsageError().
		AssertStderr("requires a name for the new vault")
}

func TestDefaultPrintsTheOnlyVault(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	l.Run("vault", "default").AssertOK().AssertStdoutEquals("personal")
	l.Run("vault", "default", "--path").AssertOK().AssertStdoutEquals(l.VaultPath("personal"))
}

// A caller reading the default vault out of this command gets an error rather
// than an empty line and a success.
func TestDefaultFailsWhenNoVaultsExist(t *testing.T) {
	l := newLab(t)
	l.Run("vault", "default").
		AssertFailed().
		AssertStdoutEquals("").
		AssertStderr("no vaults found")
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
	r := l.Run("vault", "ls").AssertOK()
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

	l.Run("vault", "ls").
		AssertOK().
		AssertStdoutEquals("").
		AssertStderr("personal.backup")
}

// A vault kept on a drive that is not mounted is a symlink to a file that is
// not there. It stays a vault: listed, holding its name, and removable. Only
// the commands that have to read it fail, and a warning says why.
func TestAVaultWhoseTargetIsAwayIsStillAVault(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")
	l.createVault("away", "a password")

	awayPath := l.VaultPath("away")
	moved := filepath.Join(filepath.Dir(l.VaultDir()), filepath.Base(awayPath))
	if err := os.Rename(awayPath, moved); err != nil {
		t.Fatalf("failed to move the vault off the vault directory: %s", err)
	}
	if err := os.Symlink(moved, awayPath); err != nil {
		t.Fatalf("failed to link the moved vault: %s", err)
	}
	// Both are readable while the target is in place.
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("away\npersonal")

	// Take the target away, as unmounting the drive would.
	if err := os.Rename(moved, moved+".unmounted"); err != nil {
		t.Fatalf("failed to take the target away: %s", err)
	}

	// It is still listed, and the warning says why it cannot be read.
	l.Run("vault", "ls").
		AssertOK().
		AssertStdoutEquals("away\npersonal").
		AssertStderr("symlink to a file that is not there")

	// The name is still taken, by create and by rename alike.
	l.Run("vault", "add", "away", "-p", pwFile).
		AssertFailed().
		AssertStderr("already exists")
	l.Run("vault", "rename", "personal", "away").
		AssertFailed().
		AssertStderr("already exists")

	// Reading it fails, as reading a vault mrs cannot decrypt does.
	l.Run("export", "-v", "away", "-p", pwFile).AssertFailed()

	// Put it back, and there is one vault under the name, not two.
	if err := os.Rename(moved+".unmounted", moved); err != nil {
		t.Fatalf("failed to put the target back: %s", err)
	}
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("away\npersonal")

	// And while it is away it can be got rid of, which is the way out of a
	// link whose target is never coming back.
	if err := os.Rename(moved, moved+".unmounted"); err != nil {
		t.Fatalf("failed to take the target away again: %s", err)
	}
	l.Run("vault", "rm", "away", "--yes").AssertOK()
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("personal")
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

	// And quietly: these are mrs's own files, so warning about them the way a
	// stray file is warned about would report a problem on every run.
	r := l.Run("vault", "ls").AssertOK()
	r.AssertStdoutEquals("personal")
	if r.Stderr != "" {
		t.Fatalf("expected nothing on stderr, got %q", r.Stderr)
	}
}

func TestRenamePreservesTheSecrets(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")

	l.Run("vault", "rename", "personal", "renamed").
		AssertOK().
		AssertStderr("Renamed vault personal to renamed")

	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("renamed")
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
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("personal\nwork")
}

func TestRenameRejectsAnInvalidTargetName(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	l.Run("vault", "rename", "personal", "../escape").
		AssertFailed().
		AssertStderr("invalid vault name")
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("personal")
}

func TestRenameRejectsIdenticalNames(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	l.Run("vault", "rename", "personal", "personal").AssertFailed()
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("personal")
}

func TestRenameRequiresAnExactSourceName(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	l.Run("vault", "rename", "pers", "renamed").
		AssertFailed().
		AssertStderr(`Did you mean "personal"`)
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("personal")
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

	l.Run("vault", "rm", "personal", "--yes").
		AssertOK().
		AssertStderr("Deleted vault personal")

	assertNotExists(t, vaultPath)
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("")
}

// A pipe cannot answer a question, whatever it holds. Exiting 0 without asking
// would tell the script that ran it that the delete was done, so mrs refuses
// and names the flag that answers in advance.
func TestDeleteWithoutAnAnswerKeepsTheVault(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	for _, stdin := range []string{"y\n", "n\n", "\n", ""} {
		l.RunStdin(stdin, "vault", "rm", "personal").
			AssertFailed().
			AssertStderr("stdin is not a terminal").
			AssertStderr("Use --yes")
		l.Run("vault", "ls").AssertOK().AssertStdoutEquals("personal")
	}
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

	l.Run("vault", "rm", "personal", "--yes").AssertOK()

	assertNotExists(t, backup)
}

// Removing the temporary files an interrupted write left behind is best effort.
// A command that cannot remove one says so and still does what was asked: the
// vault file is what holds the secrets, and a stale file beside it does not.
func TestALeftoverTemporaryFileThatCannotBeRemovedIsAWarningOnly(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"rm", []string{"vault", "rm", "personal", "--yes"}, ""},
		{"rename", []string{"vault", "rename", "personal", "renamed"}, "renamed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l := newLab(t)
			l.createVault("personal", "a password")
			// A non-empty directory carrying a temporary file's name: os.Remove
			// refuses it, which an ordinary temporary file never does.
			stale := l.VaultPath("personal") + ".1234.tmp"
			if err := os.Mkdir(stale, 0700); err != nil {
				t.Fatalf("failed to create the directory: %s", err)
			}
			if err := os.WriteFile(filepath.Join(stale, "child"), []byte("x"), 0600); err != nil {
				t.Fatalf("failed to write into the directory: %s", err)
			}

			l.Run(tt.args...).
				AssertOK().
				AssertStderr("failed to remove temporary files for vault personal")

			l.Run("vault", "ls").AssertOK().AssertStdoutEquals(tt.want)
		})
	}
}

func TestDeleteRequiresAnExactName(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	// The name is checked before anything is asked, so the user is never made
	// to confirm deleting something that is not a vault.
	l.RunStdin("y\n", "vault", "rm", "pers").
		AssertFailed().
		AssertStderr(`Did you mean "personal"`).
		AssertNoOutput("(y/n)")
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("personal")
}

func TestDeleteConfirmsWithTheVaultsOwnName(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	// A destructive confirmation names what will be destroyed. Reported here
	// rather than asked, there being no terminal to ask on.
	l.Run("vault", "rm", "personal").
		AssertFailed().
		AssertStderr("Delete vault personal?")
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("personal")
}

// Reading a vault takes a name prefix; changing one takes the whole name, so
// that a prefix cannot reach a vault the user did not name.
func TestReadingTakesAPrefixAndChangingTakesTheWholeName(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")

	// Reads.
	l.Run("search", "-v", "pers", "-p", pwFile, "a key").AssertOK().AssertStdout("a value")
	l.Run("export", "-v", "pers", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\na value\n")

	// Changes.
	newPw := l.PasswordFile("new.pw", "a different password")
	for _, args := range [][]string{
		{"vault", "change-password", "pers", "-p", pwFile, "-n", newPw},
		{"vault", "rename", "pers", "renamed"},
		{"vault", "rm", "pers"},
	} {
		l.RunStdin("y\n", args...).
			AssertFailed().
			AssertStderr(`Did you mean "personal"`)
	}

	// Nothing was changed by any of them.
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("personal")
	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\na value\n")
}

// A vault that is only read is named by --vault, which accepts a prefix. One
// that is created, changed or removed is named by an operand, which does not.
func TestTheVaultFlagAndOperandAreUsedConsistently(t *testing.T) {
	l := newLab(t)

	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"search"}, "or the start of one"},
		{[]string{"export"}, "or the start of one"},
		{[]string{"add"}, "or the start of one"},
		{[]string{"edit"}, "or the start of one"},
		{[]string{"vault", "change-password"}, "change-password <name>"},
		{[]string{"vault", "rm"}, "rm <name>"},
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

	l.RunStdin("y\n", "vault", "rm", "absent").
		AssertFailed().
		AssertStderr("not found")
}

// One rule for every command: an exact name wins, and short of one a prefix has
// to fit exactly one vault. Choosing between candidates alphabetically would
// read or write a vault the user did not mean.
func TestAnAmbiguousPrefixIsRefused(t *testing.T) {
	l := newLab(t)
	l.seedVault("alpha", "a password", "alpha key\nalpha value\n")
	l.seedVault("alphabet", "a password", "alphabet key\nalphabet value\n")
	pwFile := l.PasswordFile("alpha.pw", "a password")
	l.editorAppends("added key\nadded value\n")

	for _, args := range [][]string{
		{"search", "-v", "alph", "-p", pwFile, "key"},
		{"export", "-v", "alph", "-p", pwFile},
		{"add", "-v", "alph", "-p", pwFile},
		{"edit", "-v", "alph", "-p", pwFile},
	} {
		l.Run(args...).
			AssertFailed().
			AssertStderr(`"alph" begins the name of 2 vaults: alpha, alphabet`).
			AssertStderr("Use the whole name").
			AssertNoOutput("alpha value").
			AssertNoOutput("alphabet value")
	}

	// The commands that destroy or move a vault refuse a prefix outright, and
	// say which vault they think was meant.
	l.RunStdin("y\n", "vault", "rm", "alph").
		AssertFailed().
		AssertStderr(`Did you mean "alpha"?`)

	// An exact name is never ambiguous, whatever else begins with it, and nor
	// is a prefix that reaches one vault.
	l.Run("export", "-v", "alpha", "-p", pwFile).
		AssertOK().
		AssertNoOutput("begins the name of").
		AssertStdoutExactly("alpha key\nalpha value\n")
	l.Run("add", "-v", "alphab", "-p", pwFile).
		AssertOK().
		AssertStderr("added to vault alphabet\n")
}

// A vault is found by a glob on its name, so a shorter name is matched
// alongside every longer one beginning with it. A "-" sorts before the "." that
// separates a name from its salt, so "work-archive" comes first in the glob's
// order and shadowed "work" everywhere.
func TestAnExactNameIsNeverShadowedByALongerOne(t *testing.T) {
	l := newLab(t)
	workPw := l.seedVault("work", "a password", "k\nwork-value\n")
	l.seedVault("work-archive", "a password", "k\narchive-value\n")

	// Reading commands must read the vault that was named, not its neighbour.
	l.Run("export", "-v", "work", "-p", workPw).
		AssertOK().
		AssertStdoutExactly("k\nwork-value\n")
	l.Run("search", "-v", "work", "-p", workPw, "k").
		AssertOK().
		AssertStdout("work-value").
		AssertNoOutput("archive-value")

	// And writing commands must write to it. Saving to the wrong vault is the
	// same defect, but silent: only the vault named in the success message
	// would tell the user.
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
	l.Run("vault", "change-password", "work", "-p", workPw, "-n", newPw).
		AssertOK().
		AssertStderr("Changed password of vault work")

	l.Run("vault", "rename", "work", "current").AssertOK()
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("current\nwork-archive")

	l.Run("vault", "rm", "work-archive", "--yes").AssertOK()
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("current")
	l.Run("export", "-v", "current", "-p", newPw).
		AssertOK().
		AssertStdoutExactly("k\nwork-value\n")
}

func TestTheDefaultVaultNameIsNotShadowedEither(t *testing.T) {
	l := newLab(t)
	workPw := l.seedVault("work", "a password", "k\nwork-value\n")
	l.seedVault("work-archive", "a password", "k\narchive-value\n")
	l.Setenv("MRS_DEFAULT_VAULT_NAME", "work")

	l.Run("vault", "default").AssertOK().AssertStdoutEquals("work")
	l.Run("search", "-p", workPw, "k").
		AssertOK().
		AssertStdout("work-value").
		AssertNoOutput("archive-value")
}

func TestVaultNamesAreCaseSensitive(t *testing.T) {
	l := newLab(t)
	l.seedVault("Personal", "a password", "upper key\nupper value\n")
	l.seedVault("personal", "a password", "lower key\nlower value\n")

	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("Personal\npersonal")
	pwFile := l.PasswordFile("Personal.pw", "a password")
	l.Run("export", "-v", "Personal", "-p", pwFile).
		AssertOK().
		AssertStdout("upper value").
		AssertNoOutput("lower value")
}

func TestHelpDocumentsEveryCommand(t *testing.T) {
	l := newLab(t)

	root := l.Run("help").AssertOK()
	for _, c := range []string{"add", "edit", "export", "search", "vault"} {
		root.AssertCommandListed(c)
	}
	vaultHelp := l.Run("help", "vault").AssertOK()
	for _, c := range []string{"add", "change-password", "default", "ls", "rename", "rm"} {
		vaultHelp.AssertCommandListed(c)
	}
}

// A command that has no subcommands cannot have been given one, so an argument
// it does not take is reported as what it is. `mrs add "my key"` is a user
// expecting to name a secret, and "unknown command" answers a question they did
// not ask.
func TestACommandThatTakesNoArgumentsSaysSo(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")

	for _, args := range [][]string{
		{"export", "-p", pwFile, "personal"},
		{"vault", "ls", "personal"},
	} {
		l.Run(args...).
			AssertFailed().
			AssertStderr("takes no arguments").
			AssertNoOutput("unknown command")
	}

	// add and edit say more than that, because an argument given to one is a
	// user expecting to name a secret, and the answer is where secrets go.
	for _, args := range [][]string{
		{"add", "-p", pwFile, "my key"},
		{"edit", "-p", pwFile, "my key"},
	} {
		l.Run(args...).
			AssertFailed().
			AssertStderr(`takes no arguments, but got "my key"`).
			AssertStderr("Secrets are typed in your editor, not on the command line").
			AssertNoOutput("unknown command")
	}

	// But a mistyped subcommand of `mrs vault` still is an unknown command.
	l.Run("vault", "lst").AssertFailed().AssertStderr("unknown command")
}

// Without a vault there is nothing to name, so these commands report that
// rather than asking which vault to use, and point at the command that creates
// one.
func TestTheFirstRunSaysThereAreNoVaults(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	for _, args := range [][]string{
		{"add", "-p", pwFile},
		{"edit", "-p", pwFile},
		{"search", "-p", pwFile, "anything"},
		{"export", "-p", pwFile},
	} {
		l.Run(args...).
			AssertFailed().
			AssertStderr("no vaults found").
			AssertStderr("mrs vault add").
			AssertNoOutput("Vault name:")
	}
}

func TestVersionIsReported(t *testing.T) {
	l := newLab(t)

	// GoReleaser sets the version at link time; a build made any other way
	// says "dev".
	l.Run("--version").AssertOK().AssertStdout("mrs version")

	// Not -v. Cobra gives --version that shorthand unless the flag is already
	// registered, and -v is --vault on every command under mrs.
	l.Run("-v").AssertFailed().AssertStderr("unknown shorthand flag")
	l.Run("help").AssertOK().AssertNoOutput("-v, --version")
}

// The generated completion command works but is not listed, being noise beside
// this few commands.
func TestCompletionIsAvailableButNotListed(t *testing.T) {
	l := newLab(t)

	l.Run("help").AssertOK().AssertNoOutput("completion")
	l.Run("completion", "bash").AssertOK().AssertStdout("bash completion")
}

func TestCompletionOffersVaultNames(t *testing.T) {
	l := newLab(t)
	l.createVault("work", "a password")
	l.createVault("work-archive", "a password")
	l.createVault("personal", "a password")

	// Every command that names a vault offers the names there are, whether it
	// takes the name as an operand or as --vault.
	for _, args := range [][]string{
		{"__complete", "vault", "rm", ""},
		{"__complete", "vault", "change-password", ""},
		{"__complete", "vault", "rename", ""},
		{"__complete", "edit", "-v", ""},
		{"__complete", "export", "-v", ""},
	} {
		l.Run(args...).
			AssertOK().
			AssertStdout("personal\nwork\nwork-archive").
			AssertStderr("ShellCompDirectiveNoFileComp")
	}

	// A prefix narrows them, as it does when the command runs.
	l.Run("__complete", "vault", "rm", "work").
		AssertOK().
		AssertStdout("work\nwork-archive").
		AssertNoOutput("personal")

	// --vault is completed after a search term, which is an operand of its own.
	l.Run("__complete", "search", "aws", "-v", "work").
		AssertOK().
		AssertStdout("work\nwork-archive")

	// A name that no vault has yet is neither a vault name nor a file: create's
	// operand, and rename's target.
	for _, args := range [][]string{
		{"__complete", "vault", "add", ""},
		{"__complete", "vault", "rename", "work", ""},
	} {
		l.Run(args...).
			AssertOK().
			AssertNoOutput("personal").
			AssertStderr("ShellCompDirectiveNoFileComp")
	}

	// A password file is a file, so the shell goes on completing paths for it.
	l.Run("__complete", "search", "-p", "").
		AssertOK().
		AssertStderr("ShellCompDirectiveDefault")
}

func TestCompletionDoesNotWarnAboutAVaultItCannotRead(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")
	broken := filepath.Join(l.VaultDir(), "broken."+strings.Repeat("B", 32))
	if err := os.Mkdir(broken, 0700); err != nil {
		t.Fatalf("failed to create the directory: %s", err)
	}
	if err := os.WriteFile(filepath.Join(l.VaultDir(), "notavault.txt"), []byte("x"), 0600); err != nil {
		t.Fatalf("failed to write the stray file: %s", err)
	}

	// A shell asks what to offer on every Tab, and a warning there lands in the
	// middle of the line being typed. The entry is still offered, because
	// delete and rename can reach it.
	l.Run("__complete", "vault", "rm", "").
		AssertOK().
		AssertStdout("broken\npersonal").
		AssertNoOutput("Warning")
	l.Run("__complete", "edit", "-v", "").
		AssertOK().
		AssertNoOutput("Warning")

	// Asked for the list, mrs says why it cannot read them.
	l.Run("vault", "ls").
		AssertOK().
		AssertStderr("vault broken cannot be read").
		AssertStderr("notavault.txt")
}

func TestListSortsNamesIgnoringCase(t *testing.T) {
	l := newLab(t)
	for _, name := range []string{"zebra", "Apple", "mango", "_under", "Banana"} {
		l.createVault(name, "a password")
	}

	// Sorted as secrets are sorted by key. Filename order would put every
	// uppercase name ahead of every lowercase one, and "_under" between
	// "Banana" and "mango".
	l.Run("vault", "ls").
		AssertOK().
		AssertStdoutEquals("_under\nApple\nBanana\nmango\nzebra")
}

func TestTooManyOperandsSayHowManyArrived(t *testing.T) {
	l := newLab(t)

	// A name the shell split on a space is the usual way a command is given
	// more operands than it takes, and a message that only restates what was
	// wanted does not show that it happened.
	l.Run("vault", "add", "my", "vault").
		AssertUsageError().
		AssertStderr("requires a name for the new vault, but got 2 arguments: \"my\" \"vault\"")
	l.Run("vault", "rename", "a", "b", "c").
		AssertUsageError().
		AssertStderr("but got 3 arguments")
	l.Run("vault", "rm", "a", "b").
		AssertUsageError().
		AssertStderr("but got 2 arguments")

	// Too few is unchanged: there is nothing to report back.
	l.Run("vault", "add").
		AssertUsageError().
		AssertStderr("mrs vault add requires a name for the new vault").
		AssertNoOutput("arguments")
}

func TestADirectoryWhereAVaultShouldBeIsStillAVault(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")

	// A directory carrying a vault's name is not readable as a vault, and is
	// treated like every other vault mrs cannot read rather than failing the
	// whole listing: doing that would take out "personal" over an entry that
	// has nothing to do with it, and leave no way to remove the entry with mrs.
	broken := filepath.Join(l.VaultDir(), "broken."+strings.Repeat("B", 32))
	if err := os.Mkdir(broken, 0700); err != nil {
		t.Fatalf("failed to create the directory: %s", err)
	}

	l.Run("vault", "ls").
		AssertOK().
		AssertStdoutEquals("broken\npersonal").
		AssertStderr("vault broken cannot be read: a vault is a file, and this is a directory")

	// Every other vault is reachable, as it would be if the entry were not
	// there.
	l.Run("export", "-v", "personal", "-p", pwFile).AssertOK()

	// The name is taken, as a vault's name is.
	l.Run("vault", "add", "broken", "-p", pwFile).
		AssertFailed().
		AssertStderr("already exists")

	// Reading it fails, as reading any vault mrs cannot read does.
	l.Run("export", "-v", "broken", "-p", pwFile).AssertFailed()

	// And it can be removed with mrs, which is the way out.
	l.Run("vault", "rm", "broken", "--yes").AssertOK()
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("personal")
}
