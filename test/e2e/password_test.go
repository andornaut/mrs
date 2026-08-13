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

	l.Run("export", "-v", "work", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly(contents)
}

func TestExportPrintsTheSecretsInKeyOrderAfterAnEdit(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password",
		"zebra\nzebra value\n\nalpha\nalpha value\n")

	l.Run("edit", "-v", "work", "-p", pwFile).AssertOK()

	l.Run("export", "-v", "work", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("alpha\nalpha value\n\nzebra\nzebra value\n")
}

func TestExportOfAnEmptyVaultPrintsNothing(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("empty", "a password")

	l.Run("export", "-v", "empty", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("")
}

func TestExportRejectsAWrongPassword(t *testing.T) {
	l := newLab(t)
	l.seedVault("work", "a password", "a key\nthe-secret-value\n")
	wrong := l.PasswordFile("wrong.pw", "not the password")

	l.Run("export", "-v", "work", "-p", wrong).
		AssertFailed().
		AssertStderr("failed to decrypt").
		AssertNoOutput("the-secret-value")
}

func TestExportReportsAMissingVault(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	l.Run("export", "-v", "nosuch", "-p", pwFile).
		AssertFailed().
		AssertStderr("not found")
}

func TestExportLeavesTheVaultUntouched(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")
	before := readFile(t, l.VaultPath("work"))

	l.Run("export", "-v", "work", "-p", pwFile).AssertOK()

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
	r := l.RunStdin("a password\n", "export", "-v", "work").
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

	l.Run("export", "-v", "work", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly(contents)
}

func TestImportReportsAMissingFile(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	l.Run("vault", "create", "work", "-p", pwFile, "-i", l.UserHome+"/nosuch.txt").
		AssertFailed().
		AssertStderr("import file")

	// A create that failed must not leave a half-made vault behind, and must
	// not stand in the way of creating that vault properly afterwards.
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("")
	l.Run("vault", "create", "work", "-p", pwFile).AssertOK()
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("work")
}

func TestImportRefusesSecretsThatCannotBeReadBack(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")
	// One line beyond the limit that every command applies when it parses a
	// vault. Stored unchecked, it would make a vault that only export can
	// read, because add, edit and search each parse the secrets first.
	huge := l.WriteFile("huge.txt", "huge\n"+strings.Repeat("x", 17*1024*1024)+"\n")

	l.Run("vault", "create", "big", "-p", pwFile, "-i", huge).
		AssertFailed().
		AssertStderr("longer than the 16 MiB limit")

	l.Run("vault", "list").AssertOK().AssertStdoutEquals("")
}

func TestImportAcceptsALongLineWithinTheLimit(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")
	// A certificate or a token pasted without line breaks is one long line,
	// and must still import.
	long := l.WriteFile("long.txt", "cert\n"+strings.Repeat("x", 1024*1024)+"\n")

	l.Run("vault", "create", "certs", "-p", pwFile, "-i", long).AssertOK()

	// The vault is usable, not merely exportable.
	l.Run("search", "-v", "certs", "-p", pwFile, "cert").
		AssertOK().
		AssertStderr("1 secret matched")
	l.editorAppends("b key\nb value\n")
	l.Run("edit", "-v", "certs", "-p", pwFile).AssertOK()
}

func TestChangePasswordSwapsTheOldPasswordForTheNew(t *testing.T) {
	l := newLab(t)
	oldPw := l.seedVault("work", "a password", "a key\nthe-secret-value\n")
	newPw := l.PasswordFile("new.pw", "a different password")

	l.Run("vault", "change-password", "work", "-p", oldPw, "-n", newPw).
		AssertOK().
		AssertStderr("Changed password of vault work")

	l.Run("export", "-v", "work", "-p", newPw).
		AssertOK().
		AssertStdout("the-secret-value")
	l.Run("export", "-v", "work", "-p", oldPw).
		AssertFailed().
		AssertStderr("failed to decrypt")
}

func TestChangePasswordRejectsAWrongCurrentPassword(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\nthe-secret-value\n")
	wrong := l.PasswordFile("wrong.pw", "not the password")
	newPw := l.PasswordFile("new.pw", "a different password")

	l.Run("vault", "change-password", "work", "-p", wrong, "-n", newPw).
		AssertFailed().
		AssertStderr("failed to decrypt")

	// A change that did not happen leaves the old password working.
	l.Run("export", "-v", "work", "-p", pwFile).
		AssertOK().
		AssertStdout("the-secret-value")
}

func TestChangePasswordRejectsAWeakNewPassword(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\nthe-secret-value\n")
	short := l.PasswordFile("short.pw", "short")

	l.Run("vault", "change-password", "work", "-p", pwFile, "-n", short).
		AssertFailed().
		AssertStderr("at least 8 characters")

	l.Run("export", "-v", "work", "-p", pwFile).
		AssertOK().
		AssertStdout("the-secret-value")
}

func TestChangePasswordNamesTheFlagForTheNewPassword(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\nthe-secret-value\n")

	// Without --new-password-file there is nothing to read the new password
	// from, and --password-file is no help: it supplies the current one.
	l.RunStdin("a different password\n", "vault", "change-password", "work", "-p", pwFile).
		AssertFailed().
		AssertStderr("New password").
		AssertStderr("stdin is not a terminal").
		AssertStderr("--new-password-file")

	l.Run("export", "-v", "work", "-p", pwFile).
		AssertOK().
		AssertStdout("the-secret-value")
}

func TestChangePasswordReportsAMissingNewPasswordFile(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\nthe-secret-value\n")

	l.Run("vault", "change-password", "work", "-p", pwFile, "-n", l.UserHome+"/nosuch.pw").
		AssertFailed().
		AssertStderr("password file")

	l.Run("export", "-v", "work", "-p", pwFile).AssertOK()
}

func TestChangePasswordReportsAMissingVault(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	// The vault is resolved before any password is read, so this fails for the
	// right reason even without a terminal.
	l.Run("vault", "change-password", "nosuch", "-p", pwFile).
		AssertFailed().
		AssertStderr("not found")
}

func TestChangePasswordLeavesNoLockHeld(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")
	short := l.PasswordFile("short.pw", "short")

	l.Run("vault", "change-password", "work", "-p", pwFile, "-n", short).AssertFailed()

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
	l.Run("vault", "create", "work", "-p", withNewline).AssertOK()

	bare := l.PasswordFile("pw-bare", "a password")
	l.Run("export", "-v", "work", "-p", bare).AssertOK()
}

func TestAPasswordFileMayContainSpaces(t *testing.T) {
	l := newLab(t)
	// Only trailing newlines are trimmed: spaces are part of the password.
	pwFile := l.PasswordFile("pw", "  a password with spaces  ")
	l.Run("vault", "create", "work", "-p", pwFile).AssertOK()

	trimmed := l.PasswordFile("pw-trimmed", "a password with spaces")
	l.Run("export", "-v", "work", "-p", trimmed).AssertFailed()
	l.Run("export", "-v", "work", "-p", pwFile).AssertOK()
}
