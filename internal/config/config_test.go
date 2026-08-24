package config

import (
	"slices"
	"testing"
)

func TestTheEditorCommandIsSplitAsAShellWouldSplitIt(t *testing.T) {
	tests := []struct {
		name     string
		editor   string
		expected []string
	}{
		{"Default editor", "", []string{"nano"}},
		{"Only whitespace", "   ", []string{"nano"}},
		{"Custom editor", "vim", []string{"vim"}},
		{"Editor with arguments", "vim -n", []string{"vim", "-n"}},
		{"Surrounding whitespace", "  code -w  ", []string{"code", "-w"}},
		{"Repeated whitespace", "emacsclient  -t", []string{"emacsclient", "-t"}},
		{"Quoted path", `"/opt/my editor/bin" -n`, []string{"/opt/my editor/bin", "-n"}},
		{"Single quoted argument", `vim '+set noswapfile'`, []string{"vim", "+set noswapfile"}},
		{"Escaped space", `/opt/my\ editor`, []string{"/opt/my editor"}},
		{"Backslash inside single quotes", `vim '\n'`, []string{"vim", `\n`}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("VISUAL", "")
			t.Setenv("EDITOR", tt.editor)
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
		{"Neither", "", "", []string{"nano"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("VISUAL", tt.visual)
			t.Setenv("EDITOR", tt.editor)
			got := Editor()
			if !slices.Equal(got, tt.expected) {
				t.Errorf("Editor() = %q, expected %q", got, tt.expected)
			}
		})
	}
}
