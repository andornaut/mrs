package config

import (
	"os/exec"
	"slices"
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
		{"All three", []string{"vim", "vi", "nano"}, []string{"vim"}},
		{"No vim", []string{"nano", "vi"}, []string{"vi"}},
		{"Only nano", []string{"nano"}, []string{"nano"}},
		{"None on PATH", nil, []string{"vim"}},
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
		{"Default editor", "", []string{"vim"}},
		{"Only whitespace", "   ", []string{"vim"}},
		{"Custom editor", "vim", []string{"vim"}},
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
		{"Visual wins", "vim", "ed", []string{"vim"}},
		{"Visual only", "vim -n", "", []string{"vim", "-n"}},
		{"Empty visual falls through", "", "ed", []string{"ed"}},
		{"Whitespace visual falls through", "   ", "ed", []string{"ed"}},
		{"Neither", "", "", []string{"vim"}},
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
