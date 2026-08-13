package e2e

import (
	"strings"
	"testing"
)

// Capability 3: retrieving secrets with `search`, which decrypts a vault and
// prints whole secrets to stdout.

// searchVault is the vault the search tests read. Its keys differ from its
// values, so that a test can tell which of the two a search looked at.
const searchVault = "github\nuser: alice\ntoken: abc123\n\n" +
	"email\nuser: bob\npass: sekrit\n\n" +
	"bank account\npin: 9999\n"

func TestSearchPrintsTheWholeMatchingSecret(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	// A match prints the value as well as the key: retrieving a secret is the
	// point of a search, not merely knowing that it is there.
	l.Run("search", "-v", "work", "-p", pwFile, "github").
		AssertOK().
		AssertStdoutExactly("1 secret(s) matched regular expression \"(?i)github\" in vault work\n\n" +
			"github\nuser: alice\ntoken: abc123\n")
}

func TestSearchDoesNotPrintSecretsItDidNotMatch(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	l.Run("search", "-v", "work", "-p", pwFile, "github").
		AssertOK().
		AssertNoOutput("sekrit").
		AssertNoOutput("9999")
}

func TestSearchIsCaseInsensitive(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	for _, pattern := range []string{"GITHUB", "GitHub", "gItHuB"} {
		l.Run("search", "-v", "work", "-p", pwFile, pattern).
			AssertOK().
			AssertStdout("1 secret(s) matched").
			AssertStdout("token: abc123")
	}
}

func TestSearchIsCaseInsensitiveBeyondAscii(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "café ☕\nvalue: naïve\n")

	// Go's regexp folds case by unicode rules, so an accented key is found
	// however it was typed.
	for _, pattern := range []string{"café", "CAFÉ", "Café"} {
		l.Run("search", "-v", "work", "-p", pwFile, pattern).
			AssertOK().
			AssertStdout("1 secret(s) matched").
			AssertStdout("value: naïve")
	}
}

func TestSearchJoinsItsArgumentsWithWhitespace(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	// A shell splits `mrs search bank account` into two arguments and drops the
	// spacing between them, so mrs matches any run of whitespace instead.
	l.Run("search", "-v", "work", "-p", pwFile, "bank", "account").
		AssertOK().
		AssertStdoutExactly("1 secret(s) matched regular expression \"(?i)bank\\s+account\" in vault work\n\n" +
			"bank account\npin: 9999\n")
}

func TestSearchIgnoresValuesByDefault(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	// "alice" appears only in a value, so a default search does not find it.
	l.Run("search", "-v", "work", "-p", pwFile, "alice").
		AssertOK().
		AssertStdoutExactly("No secrets matched regular expression \"(?i)alice\" in vault work\n").
		AssertNoOutput("abc123")
}

func TestSearchFullLooksAtValuesToo(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	l.Run("search", "-v", "work", "-p", pwFile, "--full", "alice").
		AssertOK().
		AssertStdoutExactly("1 secret(s) matched regular expression \"(?i)alice\" in vault work\n\n" +
			"github\nuser: alice\ntoken: abc123\n")
}

func TestSearchFullHasAShortFlag(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	// -f means --full here, unlike on add and edit where it means --force.
	l.Run("search", "-v", "work", "-p", pwFile, "-f", "sekrit").
		AssertOK().
		AssertStdout("1 secret(s) matched")
}

func TestSearchPrintsEveryMatchSeparatedByABlankLine(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password",
		"alpha\nalpha value\n\nbeta\nbeta value\n\ngamma\ngamma value\n")

	// Matches are printed in key order, in the same shape as the vault itself,
	// so that the output can be fed back into `vault create --import-file`.
	l.Run("search", "-v", "work", "-p", pwFile, "a").
		AssertOK().
		AssertStdoutExactly("3 secret(s) matched regular expression \"(?i)a\" in vault work\n\n" +
			"alpha\nalpha value\n\nbeta\nbeta value\n\ngamma\ngamma value\n")
}

func TestSearchAcceptsRegularExpressionSyntax(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	// Anchors apply to the key alone, which is the first line of a secret.
	l.Run("search", "-v", "work", "-p", pwFile, "^email$").
		AssertOK().
		AssertStdout("1 secret(s) matched").
		AssertStdout("pass: sekrit")

	l.Run("search", "-v", "work", "-p", pwFile, "github|email").
		AssertOK().
		AssertStdout("2 secret(s) matched")
}

func TestSearchReportsNoMatches(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	// Finding nothing is an answer, not a failure: a script can tell the two
	// apart by the exit code.
	l.Run("search", "-v", "work", "-p", pwFile, "nothing-like-this").
		AssertOK().
		AssertStdout("No secrets matched")
}

func TestSearchOfAnEmptyVaultReportsNoMatches(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("empty", "a password")

	l.Run("search", "-v", "empty", "-p", pwFile, "anything").
		AssertOK().
		AssertStdout("No secrets matched")
}

func TestSearchRejectsAnInvalidRegularExpression(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	l.Run("search", "-v", "work", "-p", pwFile, "[").
		AssertFailed().
		AssertOutput("invalid regular expression")
}

func TestSearchRequiresAPattern(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	// Without this, a bare `mrs search` would print the whole vault.
	l.Run("search", "-v", "work", "-p", pwFile).
		AssertFailed().
		AssertOutput("requires at least 1 arg")
}

func TestSearchRejectsAWrongPassword(t *testing.T) {
	l := newLab(t)
	l.seedVault("work", "a password", searchVault)
	wrong := l.PasswordFile("wrong.pw", "not the password")

	l.Run("search", "-v", "work", "-p", wrong, "github").
		AssertFailed().
		AssertOutput("failed to decrypt").
		AssertNoOutput("abc123")
}

func TestSearchReportsAMissingVault(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	l.Run("search", "-v", "nosuch", "-p", pwFile, "github").
		AssertFailed().
		AssertOutput("not found")
}

func TestSearchAcceptsAVaultNamePrefix(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", searchVault)

	l.Run("search", "-v", "pers", "-p", pwFile, "github").
		AssertOK().
		AssertStdout("1 secret(s) matched")
}

func TestSearchLeavesTheVaultUntouched(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)
	before := readFile(t, l.VaultPath("work"))

	l.Run("search", "-v", "work", "-p", pwFile, "github").AssertOK()

	if after := readFile(t, l.VaultPath("work")); after != before {
		t.Fatal("expected a search to leave the vault file unchanged")
	}
	// A read is not a write, so it must not roll a backup either.
	assertNotExists(t, l.VaultPath("work")+".bak")
}

func TestSearchLeavesNoPlaintextBehind(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	l.Run("search", "-v", "work", "-p", pwFile, "--full", "sekrit").AssertOK()

	// Unlike add and edit, a search never needs a plaintext file at all.
	assertNoPlaintextUnder(t, l.Temp, "sekrit", "abc123")
	assertNoPlaintextUnder(t, l.VaultDir(), "sekrit", "abc123")
}

func TestSearchNeedsAPasswordItCanRead(t *testing.T) {
	l := newLab(t)
	l.seedVault("work", "a password", searchVault)

	// Piped into, mrs cannot turn off echo to read a password, so it says so
	// and names the flag that supplies one instead of failing with an errno.
	r := l.RunStdin("a password\n", "search", "-v", "work", "github").
		AssertFailed().
		AssertStderr("stdin is not a terminal").
		AssertStderr("--password-file")

	// The prompt must not reach stdout, which carries the matched secrets.
	if r.Stdout != "" {
		t.Fatalf("expected nothing on stdout, got %q", r.Stdout)
	}
}

func TestSearchReportsAMissingPasswordFile(t *testing.T) {
	l := newLab(t)
	l.seedVault("work", "a password", searchVault)

	l.Run("search", "-v", "work", "-p", l.UserHome+"/nosuch.pw", "github").
		AssertFailed().
		AssertOutput("password file")
}

func TestSearchMatchesALongLine(t *testing.T) {
	l := newLab(t)
	// A pasted certificate or token arrives as one very long line.
	long := strings.Repeat("x", 200*1024)
	pwFile := l.seedVault("work", "a password", "cert\n"+long+"\n")

	l.Run("search", "-v", "work", "-p", pwFile, "cert").
		AssertOK().
		AssertStdout("1 secret(s) matched")
}
