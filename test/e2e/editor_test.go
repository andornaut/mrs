package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// How mrs launches $EDITOR, exercised by execing a real editor process.

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

	// A path with spaces has to be quoted, as a shell would require, and the
	// argument after it still reaches the editor. Which strings split into
	// which argv is the table in internal/config.
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

	// In mrs's own wording, because the error exec returns names the command
	// too, and a bare substring would pass without mrs naming it.
	l.Run("edit", "-v", "personal", "-p", pwFile).
		AssertFailed().
		AssertStderr(`editor "no-such-editor-exists" failed`)
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

func TestVisualIsPreferredToEditor(t *testing.T) {
	l := newLab(t)
	pwFile := l.createVault("personal", "a password")

	// $VISUAL first, as git, crontab and sudoedit read them.
	l.Setenv("VISUAL", editorBin+" --visual")
	l.Setenv("EDITOR", "no-such-editor-exists")
	l.Setenv("FAKE_EDITOR_EXPECT_ARGS", "--visual")
	l.Setenv("FAKE_EDITOR_MODE", "append")
	l.Setenv("FAKE_EDITOR_CONTENT", "a key\na value\n")

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	if got := l.export("personal", pwFile); !strings.Contains(got, "a value") {
		t.Fatalf("expected the edit to be saved, got %q", got)
	}

	// An empty $VISUAL is no editor at all, so $EDITOR is what is left.
	l.Setenv("VISUAL", "")
	l.Setenv("EDITOR", editorBin+" --editor")
	l.Setenv("FAKE_EDITOR_EXPECT_ARGS", "--editor")
	l.Setenv("FAKE_EDITOR_CONTENT", "b key\nb value\n")

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()

	if got := l.export("personal", pwFile); !strings.Contains(got, "b value") {
		t.Fatalf("expected the edit to be saved, got %q", got)
	}
}
