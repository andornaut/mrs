package e2e

import (
	"strings"
	"testing"
)

// Capability 4: moving secrets and passwords in and out of a vault, with
// `vault export`, `vault create --import-file` and `vault change-password`.

func TestExportPrintsWhatWasImported(t *testing.T) {
	l := newLab(t)
	// An import is stored as the file was written, so an export returns it
	// unchanged. Only a later add or edit puts the secrets in key order.
	contents := "zebra\nzebra value\n\nalpha\nalpha value\n"
	pwFile := l.seedVault("work", "a password", contents)

	l.Run("vault", "export", "-v", "work", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly(contents)
}

func TestExportPrintsTheSecretsInKeyOrderAfterAnEdit(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password",
		"zebra\nzebra value\n\nalpha\nalpha value\n")

	l.Run("edit", "-v", "work", "-p", pwFile).AssertOK()

	l.Run("vault", "export", "-v", "work", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("alpha\nalpha value\n\nzebra\nzebra value\n")
}

func TestExportOfAnEmptyVaultPrintsNothing(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("empty", "a password")

	l.Run("vault", "export", "-v", "empty", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("")
}

func TestExportRejectsAWrongPassword(t *testing.T) {
	l := newLab(t)
	l.seedVault("work", "a password", "a key\nthe-secret-value\n")
	wrong := l.PasswordFile("wrong.pw", "not the password")

	l.Run("vault", "export", "-v", "work", "-p", wrong).
		AssertFailed().
		AssertOutput("failed to decrypt").
		AssertNoOutput("the-secret-value")
}

func TestExportReportsAMissingVault(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	l.Run("vault", "export", "-v", "nosuch", "-p", pwFile).
		AssertFailed().
		AssertOutput("not found")
}

func TestExportLeavesTheVaultUntouched(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")
	before := readFile(t, l.VaultPath("work"))

	l.Run("vault", "export", "-v", "work", "-p", pwFile).AssertOK()

	if after := readFile(t, l.VaultPath("work")); after != before {
		t.Fatal("expected an export to leave the vault file unchanged")
	}
	assertNotExists(t, l.VaultPath("work")+".bak")
}

func TestExportNeedsAPasswordItCanRead(t *testing.T) {
	l := newLab(t)
	l.seedVault("work", "a password", "a key\nthe-secret-value\n")

	// `mrs vault export > secrets` is the natural way to run this command, so
	// nothing that is not a secret may be written to stdout - least of all a
	// password prompt, which the user would never see.
	r := l.RunStdin("a password\n", "vault", "export", "-v", "work").
		AssertFailed().
		AssertStderr("stdin is not a terminal").
		AssertStderr("--password-file")

	if r.Stdout != "" {
		t.Fatalf("expected nothing on stdout, got %q", r.Stdout)
	}
}

func TestSecretsSurviveImportAndExport(t *testing.T) {
	l := newLab(t)
	// Awkward but legitimate content: indentation, trailing spaces, a blank
	// line inside no secret, and a line that begins with a "#".
	contents := "alpha\n  indented value  \n#not a comment\n\nbeta\nbeta value\n"
	pwFile := l.seedVault("work", "a password", contents)

	l.Run("vault", "export", "-v", "work", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly(contents)
}

func TestImportReportsAMissingFile(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	l.Run("vault", "create", "-v", "work", "-p", pwFile, "-i", l.UserHome+"/nosuch.txt").
		AssertFailed().
		AssertOutput("import file")

	// A create that failed must not leave a half-made vault behind, and must
	// not stand in the way of creating that vault properly afterwards.
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("")
	l.Run("vault", "create", "-v", "work", "-p", pwFile).AssertOK()
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("work")
}

func TestChangePasswordNeedsATerminalForTheNewPassword(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\nthe-secret-value\n")

	// --password-file supplies the current password, but there is no flag for
	// the new one, so change-password cannot run unattended. It must say that
	// plainly rather than reporting an ioctl error, and it must not point at
	// --password-file, which would not help here.
	l.RunStdin("new password\nnew password\n", "vault", "change-password", "-v", "work", "-p", pwFile).
		AssertFailed().
		AssertStderr("New password").
		AssertStderr("stdin is not a terminal").
		AssertNoOutput("--password-file")

	// A change that could not happen leaves the old password working.
	l.Run("vault", "export", "-v", "work", "-p", pwFile).
		AssertOK().
		AssertStdout("the-secret-value")
}

func TestChangePasswordReportsAMissingVault(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	// The vault is resolved before any password is read, so this fails for the
	// right reason even without a terminal.
	l.Run("vault", "change-password", "-v", "nosuch", "-p", pwFile).
		AssertFailed().
		AssertOutput("not found")
}

func TestChangePasswordLeavesNoLockHeld(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")

	l.RunStdin("", "vault", "change-password", "-v", "work", "-p", pwFile).AssertFailed()

	// A command that failed must not lock the vault out of later writes.
	l.editorAppends("b key\nb value\n")
	l.Run("edit", "-v", "work", "-p", pwFile).AssertOK()
	if got := l.export("work", pwFile); !strings.Contains(got, "b value") {
		t.Fatalf("expected the later edit to be saved, got %q", got)
	}
}

func TestAPasswordFileMayEndWithANewline(t *testing.T) {
	l := newLab(t)
	// `echo secret > pw` leaves a trailing newline that is not part of the
	// password, so a vault created that way is readable with either form.
	withNewline := l.PasswordFile("pw-newline", "a password\n")
	l.Run("vault", "create", "-v", "work", "-p", withNewline).AssertOK()

	bare := l.PasswordFile("pw-bare", "a password")
	l.Run("vault", "export", "-v", "work", "-p", bare).AssertOK()
}

func TestAPasswordFileMayContainSpaces(t *testing.T) {
	l := newLab(t)
	// Only trailing newlines are trimmed: spaces are part of the password.
	pwFile := l.PasswordFile("pw", "  a password with spaces  ")
	l.Run("vault", "create", "-v", "work", "-p", pwFile).AssertOK()

	trimmed := l.PasswordFile("pw-trimmed", "a password with spaces")
	l.Run("vault", "export", "-v", "work", "-p", trimmed).AssertFailed()
	l.Run("vault", "export", "-v", "work", "-p", pwFile).AssertOK()
}
