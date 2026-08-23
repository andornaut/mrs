package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Capability 2: authoring secrets with `add` and `edit`, through a real editor
// process editing a real plaintext file.

func TestAddWritesSecretsToAnEmptyVault(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")
	l.editorWrites("zebra key\nzebra value\n\nalpha key\nalpha value\n")

	l.Run("add", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStderr("2 secrets added to vault personal")

	// Secrets are sorted by key, case-insensitively.
	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("alpha key\nalpha value\n\nzebra key\nzebra value\n")
}

func TestAddKeepsTheExistingSecrets(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "existing key\nexisting value\n")
	l.editorWrites("new key\nnew value\n")

	l.Run("add", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStderr("1 secret added")

	got := l.export("personal", pwFile)
	for _, want := range []string{"existing value", "new value"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected the vault to contain %q, got %q", want, got)
		}
	}
}

func TestAddShowsTheEditorOnlyTheNewSecrets(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "existing key\nexisting value\n")
	input := l.captureEditorInput()

	l.Run("add", "-v", "personal", "-p", pwFile).AssertOK()

	// Unlike edit, add must not put the existing secrets in front of the user,
	// nor leave them in a plaintext file for longer than needed.
	if got := input(); strings.Contains(got, "existing value") {
		t.Fatalf("expected add not to show the existing secrets, got %q", got)
	}
}

func TestAddReportsWhenNothingWasAdded(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")
	l.Setenv("FAKE_EDITOR_MODE", "noop")

	l.Run("add", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStderr("No secrets added to vault personal")
}

func TestEditShowsTheEditorTheExistingSecrets(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")
	input := l.captureEditorInput()

	l.Run("edit", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStderr("Saved changes to vault personal")

	if got := input(); !strings.Contains(got, "a value") {
		t.Fatalf("expected edit to show the existing secrets, got %q", got)
	}
}

func TestEditReplacesTheSecrets(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "old key\nold value\n")
	l.editorWrites("new key\nnew value\n")

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("new key\nnew value\n").
		AssertNoOutput("old value")
}

func TestEditToEmptyIsConfirmedFirst(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n\nb key\nb value\n")
	l.Setenv("FAKE_EDITOR_MODE", "clear")

	l.Run("edit", "-v", "personal", "-p", pwFile, "--yes").
		AssertOK().
		AssertStderr("Saved changes to vault personal")

	l.Run("export", "-v", "personal", "-p", pwFile).AssertOK().AssertStdoutEquals("")
	// The backup written before the save is the user's way back.
	if _, err := os.Stat(l.VaultPath("personal") + ".bak"); err != nil {
		t.Fatalf("expected a backup of the emptied vault: %s", err)
	}
}

func TestEditToEmptyIsRefusedByDefault(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")
	l.Setenv("FAKE_EDITOR_MODE", "clear")

	// A pipe cannot answer the question, so mrs refuses rather than saving,
	// and says both what it was asking and how to answer.
	for _, stdin := range []string{"y\n", "n\n", ""} {
		l.RunStdin(stdin, "edit", "-v", "personal", "-p", pwFile).
			AssertFailed().
			AssertStderr("remove all 1 secret from vault personal").
			AssertStderr("Use --yes").
			AssertNoOutput("Saved changes")

		if got := l.export("personal", pwFile); !strings.Contains(got, "a value") {
			t.Fatalf("expected the secrets to survive, got %q", got)
		}
	}
}

func TestAnEditThatRemovesSomeSecretsIsNotConfirmed(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n\nb key\nb value\n")
	l.editorWrites("a key\na value\n")

	// Only emptying a vault is confirmed; an ordinary edit is not interrupted.
	l.Run("edit", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStderr("Saved changes")

	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\na value\n")
}

func TestACommentLineIsKeptAsASecret(t *testing.T) {
	l := newLab(t)
	// A key such as "#1 bank pin" is content, not a comment, so no edit may
	// drop it - not even one that changed nothing.
	pwFile := l.seedVault("personal", "a password", "#1 bank pin\npin: 4321\n")
	l.Setenv("FAKE_EDITOR_MODE", "noop")

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("#1 bank pin\npin: 4321\n")
	l.Run("search", "bank", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdout("pin: 4321")
}

func TestTheInstructionsAreStrippedEvenIfPartlyDeleted(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")
	// An editor session in which the user deleted one instruction line and
	// wrote a comment of their own above their first secret.
	l.editorWrites("# The first line of each secret is its unique key.\n\n# my own note\na key\na value\n")

	l.Run("add", "-v", "personal", "-p", pwFile).AssertOK()

	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("# my own note\na key\na value\n")
}

func TestWhitespaceWithinASecretIsPreserved(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")
	// A value that is indented, or that ends in a space, must survive intact.
	content := "ssh config\n    IdentityFile ~/.ssh/id\npassword: trailing  \n"
	l.editorWrites(content)

	l.Run("add", "-v", "personal", "-p", pwFile).AssertOK()

	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly(content)
}

func TestDuplicateKeysAreReported(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "shared key\nfirst value\n")
	l.editorWrites("shared key\nsecond value\n")

	l.Run("add", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStderr(`2 secrets share the key "shared key"`)

	// Both are kept, and a search returns both.
	l.Run("search", "shared", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdout("first value").
		AssertStdout("second value")
}

func TestEditSurvivesAnEditorThatRemovesTheFile(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")
	l.Setenv("FAKE_EDITOR_MODE", "delete")

	// The error names the file the editor was given, rather than reporting a
	// temporary path the user has never seen.
	l.Run("edit", "-v", "personal", "-p", pwFile).
		AssertFailed().
		AssertStderr("could not read back the file the editor was given")

	if got := l.export("personal", pwFile); !strings.Contains(got, "a value") {
		t.Fatalf("expected the secrets to survive, got %q", got)
	}
}

func TestInstructionsAreShownAndNeverSaved(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")
	input := l.captureEditorInput()
	l.editorAppends("a key\na value\n")

	l.Run("add", "-v", "personal", "-p", pwFile).AssertOK()

	if got := input(); !strings.Contains(got, "# Secrets are separated by blank lines.") {
		t.Fatalf("expected the editor to be shown the instructions, got %q", got)
	}
	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\na value\n")
}

func TestInstructionsCanBeHidden(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")
	l.Setenv("MRS_HIDE_EDITOR_INSTRUCTIONS", "1")
	input := l.captureEditorInput()

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	// The secrets alone, with nothing prepended to them.
	if got := input(); got != "a key\na value\n" {
		t.Fatalf("expected the editor to be shown the secrets alone, got %q", got)
	}
}

func TestSecretsSurviveARoundTrip(t *testing.T) {
	contents := map[string]string{
		"unicode":            "パスワード\n🔐 emoji value\nÜmlaut: naïve café\n",
		"punctuation":        "key: with: colons\nvalue = a\\b/c\"d'e`f$g\n",
		"a long value":       "long key\n" + strings.Repeat("0123456789abcdef", 4096) + "\n",
		"many lines":         "many lines key\n" + strings.Repeat("a line\n", 500),
		"tabs within a line": "tab key\nuser\tpassword\n",
		"control characters": "control key\nbell\aform\ffeed\vvertical\n",
	}
	for desc, content := range contents {
		t.Run(desc, func(t *testing.T) {
			l := newLab(t)
			pwFile := l.createVault("personal", "a password")
			l.editorWrites(content)

			l.Run("add", "-v", "personal", "-p", pwFile).AssertOK()

			l.Run("export", "-v", "personal", "-p", pwFile).
				AssertOK().
				AssertStdoutExactly(content)
		})
	}
}

func TestANullByteInAValueSurvivesAnEdit(t *testing.T) {
	l := newLab(t)
	// A value can hold arbitrary bytes. This one arrives by import, because an
	// environment variable, which is how the fake editor is handed its
	// content, cannot carry a null.
	content := "binary key\nbefore\x00after\nplain line\n"
	pwFile := l.seedVault("personal", "a password", content)

	// The editor changes nothing, so anything lost is lost by mrs parsing the
	// secrets and writing them back.
	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly(content)
}

func TestSecretsAreSeparatedByBlankLines(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")
	// Repeated and whitespace-only separators are all one separator, and
	// leading and trailing blank lines are discarded.
	l.editorWrites("\n\nfirst key\nfirst value\n\n \t \n\nsecond key\nsecond value\n\n\n")

	l.Run("add", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStderr("2 secrets added")

	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("first key\nfirst value\n\nsecond key\nsecond value\n")
}

func TestWindowsLineEndingsAreAccepted(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")
	l.editorWrites("a key\r\na value\r\n\r\nb key\r\nb value\r\n")

	l.Run("add", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStderr("2 secrets added")

	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\na value\n\nb key\nb value\n")
}

func TestAddReportsAMissingVault(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	l.Run("add", "-v", "absent", "-p", pwFile).AssertFailed().AssertStderr("not found")
	l.Run("edit", "-v", "absent", "-p", pwFile).AssertFailed().AssertStderr("not found")
}

func TestAddRejectsAWrongPassword(t *testing.T) {
	l := newLab(t)
	l.seedVault("personal", "a password", "a key\na value\n")
	wrong := l.PasswordFile("wrong.pw", "another password")
	l.editorWrites("new key\nnew value\n")

	l.Run("add", "-v", "personal", "-p", wrong).
		AssertFailed().
		AssertStderr("failed to decrypt")
	l.Run("edit", "-v", "personal", "-p", wrong).
		AssertFailed().
		AssertStderr("failed to decrypt")

	// A wrong password must never overwrite the secrets it could not read.
	correct := l.PasswordFile("personal.pw", "a password")
	if got := l.export("personal", correct); !strings.Contains(got, "a value") {
		t.Fatalf("expected the secrets to survive, got %q", got)
	}
}

func TestAVaultWithALongLineStaysUsable(t *testing.T) {
	l := newLab(t)
	// A certificate or token pasted without line breaks. Such a vault can be
	// created by import and read by export, so add, edit and search must not
	// refuse it.
	long := strings.Repeat("A", 200_000)
	pwFile := l.seedVault("personal", "a password", "tls cert\n"+long+"\n")

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()
	l.Run("search", "cert", "-v", "personal", "-p", pwFile).AssertOK().AssertStderr("1 secret matched")

	l.editorAppends("another key\nanother value\n")
	l.Run("add", "-v", "personal", "-p", pwFile).AssertOK()

	if got := l.export("personal", pwFile); !strings.Contains(got, long) {
		t.Fatal("expected the long line to survive an edit")
	}
}

// assertNoPlaintextUnder walks a directory and fails if any file contains one
// of the given secrets.
func assertNoPlaintextUnder(t *testing.T, dir string, secrets ...string) {
	t.Helper()
	// Read through a root so that each file is reached by a path relative to
	// the tree being walked, rather than by the absolute one the walk hands
	// back after having already stat'd it.
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("failed to open %s: %s", dir, err)
	}
	defer func() { _ = root.Close() }()

	err = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		b, err := root.ReadFile(rel)
		if err != nil {
			return err
		}
		for _, s := range secrets {
			if strings.Contains(string(b), s) {
				t.Errorf("found plaintext %q in %s", s, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk %s: %s", dir, err)
	}
}

func TestDuplicateKeysAreReportedOnImport(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")

	// An import is where duplicates arrive, so it is the moment the warning is
	// most worth having. Hearing it only on the next save would be hearing it
	// about a file the user no longer has in hand.
	importFile := l.WriteFile("import.txt", "shared key\nfirst value\n\nshared key\nsecond value\n")

	l.Run("vault", "create", "personal", "-p", pwFile, "-i", importFile).
		AssertOK().
		AssertStderr(`2 secrets share the key "shared key"`)

	// The file is stored as it was written, so importing it did not reorder it.
	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("shared key\nfirst value\n\nshared key\nsecond value\n")

	// An import without duplicates says nothing.
	clean := l.WriteFile("clean.txt", "a key\na value\n\nb key\nb value\n")
	l.Run("vault", "create", "other", "-p", pwFile, "-i", clean).
		AssertOK().
		AssertNoOutput("share the key")
}
