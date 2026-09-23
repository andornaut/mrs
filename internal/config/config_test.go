package config

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// stubLookPath makes the fallback deterministic, whatever is installed on the
// machine running the tests: only the named editors are on PATH.
func stubLookPath(t *testing.T, present ...string) {
	t.Helper()
	original := lookPath
	t.Cleanup(func() { lookPath = original })
	lookPath = func(name string) (string, error) {
		if slices.Contains(present, name) {
			return "/usr/bin/" + name, nil
		}
		return "", exec.ErrNotFound
	}
}

func TestTheFallbackEditorIsTheFirstOneOnPath(t *testing.T) {
	tests := []struct {
		name     string
		present  []string
		expected []string
	}{
		{"All three", []string{"vim", "vi", "nano"}, []string{"vim", "-n", "-i", "NONE"}},
		{"No vim", []string{"nano", "vi"}, []string{"vi"}},
		{"Only nano", []string{"nano"}, []string{"nano"}},
		{"None on PATH", nil, []string{"vim", "-n", "-i", "NONE"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("VISUAL", "")
			t.Setenv("EDITOR", "")
			stubLookPath(t, tt.present...)
			got := Editor()
			if !slices.Equal(got, tt.expected) {
				t.Errorf("Editor() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestTheEditorCommandIsSplitAsAShellWouldSplitIt(t *testing.T) {
	tests := []struct {
		name     string
		editor   string
		expected []string
	}{
		// "ed" is off the stubbed PATH, so this case fails if $EDITOR is
		// ignored; the fallback would answer "vim".
		{"Custom editor", "ed", []string{"ed"}},
		{"Editor with arguments", "vim -n", []string{"vim", "-n"}},
		{"Surrounding whitespace", "  code -w  ", []string{"code", "-w"}},
		{"Repeated whitespace", "emacsclient  -t", []string{"emacsclient", "-t"}},
		{"Tab between arguments", "emacsclient\t-t", []string{"emacsclient", "-t"}},
		{"Quoted path", `"/opt/my editor/bin" -n`, []string{"/opt/my editor/bin", "-n"}},
		{"Single quoted argument", `vim '+set noswapfile'`, []string{"vim", "+set noswapfile"}},
		{"Escaped space", `/opt/my\ editor`, []string{"/opt/my editor"}},
		{"Backslash inside single quotes", `vim '\n'`, []string{"vim", `\n`}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("VISUAL", "")
			t.Setenv("EDITOR", tt.editor)
			stubLookPath(t, "vim", "vi", "nano")
			got := Editor()
			if !slices.Equal(got, tt.expected) {
				t.Errorf("Editor() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestVisualIsPreferredToEditorUnlessItIsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		visual   string
		editor   string
		expected []string
	}{
		// "emacs" is off the stubbed PATH, so this case fails if both
		// variables are ignored; the fallback would answer "vim".
		{"Visual wins", "emacs", "ed", []string{"emacs"}},
		{"Visual only", "vim -n", "", []string{"vim", "-n"}},
		{"Empty visual falls through", "", "ed", []string{"ed"}},
		{"Whitespace visual falls through", "   ", "ed", []string{"ed"}},
		{"Neither", "", "", []string{"vim", "-n", "-i", "NONE"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("VISUAL", tt.visual)
			t.Setenv("EDITOR", tt.editor)
			stubLookPath(t, "vim", "vi", "nano")
			got := Editor()
			if !slices.Equal(got, tt.expected) {
				t.Errorf("Editor() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

// The temporary directory is created once and remembered: a second caller gets
// the same directory, and cleanup reads what was created without creating one.
// A directory per call would be a directory the cleanup on exit never removes.
func TestTheTempDirIsCreatedOnceAndRememberedForCleanup(t *testing.T) {
	Reset()
	t.Cleanup(Reset)
	t.Setenv("MRS_TEMP", t.TempDir())

	if got := CreatedTempDir(); got != "" {
		t.Fatalf("CreatedTempDir() before any GetTempDir() = %q, want \"\"", got)
	}
	first, err := GetTempDir()
	if err != nil {
		t.Fatalf("GetTempDir() error: %v", err)
	}
	second, err := GetTempDir()
	if err != nil {
		t.Fatalf("GetTempDir() error: %v", err)
	}
	if first != second {
		t.Errorf("GetTempDir() = %q then %q, want the same directory", first, second)
	}
	if got := CreatedTempDir(); got != first {
		t.Errorf("CreatedTempDir() = %q, want the created directory %q", got, first)
	}
}

// The directory the per-run directories sit in must be this user's own: one
// that another user made first, or a symlink someone put in its place, would
// let them swap the directory holding plaintext for one of their own.
func TestTheTempDirParentMustBeAPrivateDirectory(t *testing.T) {
	t.Run("A parent open to others is narrowed", func(t *testing.T) {
		Reset()
		t.Cleanup(Reset)
		base := t.TempDir()
		t.Setenv("MRS_TEMP", base)
		parent := filepath.Join(base, "mrs")
		if err := os.Mkdir(parent, 0755); err != nil {
			t.Fatal(err)
		}
		// The umask may have narrowed the Mkdir.
		if err := os.Chmod(parent, 0755); err != nil {
			t.Fatal(err)
		}

		if _, err := GetTempDir(); err != nil {
			t.Fatalf("GetTempDir() error: %v", err)
		}
		fi, err := os.Stat(parent)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0700 {
			t.Errorf("parent mode = %o, want 0700", got)
		}
	})

	t.Run("A symlink in the parent's place is refused", func(t *testing.T) {
		Reset()
		t.Cleanup(Reset)
		base := t.TempDir()
		t.Setenv("MRS_TEMP", base)
		elsewhere := t.TempDir()
		if err := os.Symlink(elsewhere, filepath.Join(base, "mrs")); err != nil {
			t.Fatal(err)
		}

		_, err := GetTempDir()
		if err == nil || !strings.Contains(err.Error(), "not a directory owned by you") {
			t.Fatalf("GetTempDir() error = %v, want a refusal of the symlink", err)
		}
		if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
			t.Errorf("a run directory was made through the symlink: %v", entries)
		}
	})

	// The system temporary directory is shared by every user, so the parent
	// there carries the user's id.
	t.Run("The system temporary directory gets a parent per user", func(t *testing.T) {
		Reset()
		t.Cleanup(Reset)
		base := t.TempDir()
		t.Setenv("MRS_TEMP", "")
		t.Setenv("XDG_RUNTIME_DIR", "")
		t.Setenv("TMPDIR", base)

		p, err := GetTempDir()
		if err != nil {
			t.Fatalf("GetTempDir() error: %v", err)
		}
		if want := filepath.Join(base, fmt.Sprintf("mrs-%d", os.Geteuid())); filepath.Dir(p) != want {
			t.Errorf("GetTempDir() = %q, want a directory in %q", p, want)
		}
	})
}
