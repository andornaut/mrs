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
	// point of a search, not merely knowing that it is there. The secrets go to
	// stdout alone, so the output can be redirected or piped as it is.
	l.Run("search", "-v", "work", "-p", pwFile, "github").
		AssertOK().
		AssertStdoutExactly("github\nuser: alice\ntoken: abc123\n").
		AssertStderr("1 secret matched \"github\" in vault work")
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
			AssertStderr("1 secret matched").
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
			AssertStderr("1 secret matched").
			AssertStdout("value: naïve")
	}
}

func TestSearchJoinsItsArgumentsWithWhitespace(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	// A shell splits `mrs search bank account` into two arguments and drops the
	// spacing between them, so mrs matches any run of whitespace instead. The
	// report quotes what the user typed, not the pattern mrs built from it.
	l.Run("search", "-v", "work", "-p", pwFile, "bank", "account").
		AssertOK().
		AssertStdoutExactly("bank account\npin: 9999\n").
		AssertStderr("1 secret matched \"bank account\" in vault work").
		AssertNoOutput("\\s+").
		AssertNoOutput("(?i)")
}

func TestSearchIgnoresValuesByDefault(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	// "alice" appears only in a value, so a default search does not find it.
	l.Run("search", "-v", "work", "-p", pwFile, "alice").
		AssertFailed().
		AssertStdoutExactly("").
		AssertStderr("No secrets matched \"alice\" in vault work").
		AssertNoOutput("abc123")
}

func TestSearchFullLooksAtValuesToo(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	l.Run("search", "-v", "work", "-p", pwFile, "--full", "alice").
		AssertOK().
		AssertStdoutExactly("github\nuser: alice\ntoken: abc123\n").
		AssertStderr("1 secret matched \"alice\" in vault work")
}

func TestSearchFullHasAShortFlag(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	l.Run("search", "-v", "work", "-p", pwFile, "-f", "sekrit").
		AssertOK().
		AssertStderr("1 secret matched")

	// -f is --full, and nothing else. No command has a short form for --force,
	// so the letter means one thing wherever it appears.
	l.Run("search", "-v", "work", "-p", pwFile, "-a", "sekrit").
		AssertFailed().
		AssertStderr("unknown shorthand flag")
}

func TestSearchPrintsEveryMatchSeparatedByABlankLine(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password",
		"alpha\nalpha value\n\nbeta\nbeta value\n\ngamma\ngamma value\n")

	// Matches are printed in key order, in the same shape as the vault itself,
	// and on stdout alone, so that the output can be fed straight back into
	// `vault create --import-file`.
	l.Run("search", "-v", "work", "-p", pwFile, "a").
		AssertOK().
		AssertStdoutExactly("alpha\nalpha value\n\nbeta\nbeta value\n\ngamma\ngamma value\n").
		AssertStderr("3 secrets matched \"a\" in vault work")
}

func TestSearchAcceptsRegularExpressionSyntax(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	// Anchors apply to the key alone, which is the first line of a secret.
	l.Run("search", "-v", "work", "-p", pwFile, "^email$").
		AssertOK().
		AssertStderr("1 secret matched").
		AssertStdout("pass: sekrit")

	l.Run("search", "-v", "work", "-p", pwFile, "github|email").
		AssertOK().
		AssertStderr("2 secrets matched")
}

func TestSearchReportsNoMatches(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	// Finding nothing is not a failure and is not reported as one, but it
	// exits non-zero so that a script can tell it from finding something, as
	// it can with grep.
	r := l.Run("search", "-v", "work", "-p", pwFile, "nothing-like-this").
		AssertFailed().
		AssertStderr("No secrets matched \"nothing-like-this\" in vault work").
		AssertNoOutput("Error")
	if r.Stdout != "" {
		t.Fatalf("expected nothing on stdout, got %q", r.Stdout)
	}
}

func TestSearchOfAnEmptyVaultReportsNoMatches(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("empty", "a password")

	l.Run("search", "-v", "empty", "-p", pwFile, "anything").
		AssertFailed().
		AssertStderr("No secrets matched")
}

func TestSearchOutputCanBeRedirectedOnItsOwn(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	// stdout carries the matched secrets and nothing else, in the same shape a
	// vault is written in, so a search can be piped or redirected as it stands.
	r := l.Run("search", "-v", "work", "-p", pwFile, "email", "--full").AssertOK()
	l.Run("vault", "create", "copy", "-p", pwFile,
		"-i", l.WriteFile("from-search.txt", r.Stdout)).AssertOK()
	l.Run("export", "-v", "copy", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("email\nuser: bob\npass: sekrit\n")
}

func TestSearchReportsWhatWasTypedNotThePatternItBuilt(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	// mrs lowercases the match and joins the arguments itself, so reporting
	// the compiled pattern would show the user a search they did not write.
	r := l.Run("search", "-v", "work", "-p", pwFile, "BANK", "account").AssertOK()
	for _, unwanted := range []string{"(?i)", `\s+`, "regular expression"} {
		if strings.Contains(r.Stderr, unwanted) {
			t.Errorf("expected the report not to contain %q, got %q", unwanted, r.Stderr)
		}
	}
	r.AssertStderr(`matched "BANK account" in vault work`)
}

func TestSearchCountsAreSingularOrPlural(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	l.Run("search", "-v", "work", "-p", pwFile, "github").
		AssertOK().
		AssertStderr("1 secret matched").
		AssertNoOutput("secret(s)")
	l.Run("search", "-v", "work", "-p", pwFile, "a").
		AssertOK().
		AssertStderr("2 secrets matched").
		AssertNoOutput("secret(s)")

	// add reports the same way.
	l.editorWrites("one key\none value\n")
	l.Run("add", "-v", "work", "-p", pwFile).
		AssertOK().
		AssertStderr("1 secret added").
		AssertNoOutput("secret(s)")
	l.editorWrites("two key\ntwo value\n\nthree key\nthree value\n")
	l.Run("add", "-v", "work", "-p", pwFile).
		AssertOK().
		AssertStderr("2 secrets added").
		AssertNoOutput("secret(s)")
}

func TestSearchRejectsAnInvalidRegularExpression(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	l.Run("search", "-v", "work", "-p", pwFile, "[").
		AssertFailed().
		AssertStderr("invalid regular expression")
}

func TestSearchRequiresAPattern(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)

	// Without this, a bare `mrs search` would print the whole vault. The
	// message names the command and what it wanted, rather than counting
	// arguments, as every other argument error does.
	l.Run("search", "-v", "work", "-p", pwFile).
		AssertFailed().
		AssertStderr("mrs search requires a regular expression")
}

func TestSearchRejectsAWrongPassword(t *testing.T) {
	l := newLab(t)
	l.seedVault("work", "a password", searchVault)
	wrong := l.PasswordFile("wrong.pw", "not the password")

	l.Run("search", "-v", "work", "-p", wrong, "github").
		AssertFailed().
		AssertStderr("failed to decrypt").
		AssertNoOutput("abc123")
}

func TestSearchReportsAMissingVault(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	l.Run("search", "-v", "nosuch", "-p", pwFile, "github").
		AssertFailed().
		AssertStderr("not found")
}

func TestSearchAcceptsAVaultNamePrefix(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", searchVault)

	l.Run("search", "-v", "pers", "-p", pwFile, "github").
		AssertOK().
		AssertStderr("1 secret matched")
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
		AssertStderr("password file")
}

func TestSearchMatchesALongLine(t *testing.T) {
	l := newLab(t)
	// A pasted certificate or token arrives as one very long line.
	long := strings.Repeat("x", 200*1024)
	pwFile := l.seedVault("work", "a password", "cert\n"+long+"\n")

	l.Run("search", "-v", "work", "-p", pwFile, "cert").
		AssertOK().
		AssertStderr("1 secret matched")
}
