package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// How mrs launches $EDITOR, exercised by execing a real editor process.

func TestEditorMayCarryArguments(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")

	// $EDITOR commonly carries arguments, as in "vim -n" or "code -w".
	l.Setenv("EDITOR", editorBin+" -n --wait")
	l.Setenv("FAKE_EDITOR_EXPECT_ARGS", "-n --wait")
	l.Setenv("FAKE_EDITOR_MODE", "append")
	l.Setenv("FAKE_EDITOR_CONTENT", "a key\na value\n")

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	if got := l.export("personal", pwFile); !strings.Contains(got, "a value") {
		t.Fatalf("expected the edit to be saved, got %q", got)
	}
}

func TestEditorPathMayContainSpaces(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")

	dir := filepath.Join(l.UserHome, "my editors")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("failed to create %s: %s", dir, err)
	}
	spaced := filepath.Join(dir, "my editor")
	b, err := os.ReadFile(editorBin)
	if err != nil {
		t.Fatalf("failed to read the fake editor: %s", err)
	}
	if err := os.WriteFile(spaced, b, 0700); err != nil {
		t.Fatalf("failed to write %s: %s", spaced, err)
	}

	// A path with spaces has to be quoted, as a shell would require.
	l.Setenv("EDITOR", `"`+spaced+`" -n`)
	l.Setenv("FAKE_EDITOR_EXPECT_ARGS", "-n")
	l.Setenv("FAKE_EDITOR_MODE", "append")
	l.Setenv("FAKE_EDITOR_CONTENT", "a key\na value\n")

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	if got := l.export("personal", pwFile); !strings.Contains(got, "a value") {
		t.Fatalf("expected the edit to be saved, got %q", got)
	}
}

func TestAMissingEditorIsReportedClearly(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")
	l.Setenv("EDITOR", "no-such-editor-exists")

	l.Run("edit", "-v", "personal", "-p", pwFile).
		AssertFailed().
		AssertStderr("no-such-editor-exists")
}

func TestAFailingEditorLeavesTheVaultUnchanged(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")
	before := readFile(t, l.VaultPath("personal"))

	l.Setenv("FAKE_EDITOR_MODE", "fail")
	l.Run("edit", "-v", "personal", "-p", pwFile).AssertFailed()

	if after := readFile(t, l.VaultPath("personal")); after != before {
		t.Fatal("expected a failed editor session to leave the vault untouched")
	}
	if got := l.export("personal", pwFile); !strings.Contains(got, "a value") {
		t.Fatalf("expected the secrets to survive, got %q", got)
	}
}

// An editor opens with the cursor on the first line, so typing straight into an
// `mrs add` session pushes the instructions below what was typed. Removing them
// only when they come first would encrypt them as part of the secret.
func TestInstructionsAreRemovedWhereverTheyEndUp(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")
	l.Unsetenv("MRS_HIDE_EDITOR_INSTRUCTIONS")
	l.Setenv("FAKE_EDITOR_MODE", "prepend")
	l.Setenv("FAKE_EDITOR_CONTENT", "top key\ntop value\n")

	l.Run("add", "-v", "personal", "-p", pwFile).AssertOK().AssertStderr("1 secret added")

	l.Run("export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("top key\ntop value\n").
		AssertNoOutput("# Secrets are separated by blank lines.")
}
