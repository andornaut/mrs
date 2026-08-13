package config

import (
	"os"
	"path"
	"slices"
	"strings"
	"testing"
)

func TestGetBaseDir(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		expected string
	}{
		{
			name: "MRS_HOME set",
			env: map[string]string{
				"MRS_HOME": "/tmp/mrs-home",
			},
			expected: "/tmp/mrs-home",
		},
		{
			name: "XDG_DATA_HOME set",
			env: map[string]string{
				"MRS_HOME":      "",
				"XDG_DATA_HOME": "/tmp/xdg-data",
			},
			expected: "/tmp/xdg-data/mrs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Reset()
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			got, err := GetBaseDir()
			if err != nil {
				t.Fatalf("GetBaseDir() error = %v", err)
			}
			if got != tt.expected {
				t.Errorf("GetBaseDir() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestGetVaultDir(t *testing.T) {
	Reset()
	tmpHome := t.TempDir()
	t.Setenv("MRS_HOME", tmpHome)

	got, err := GetVaultDir()
	if err != nil {
		t.Fatalf("GetVaultDir() error = %v", err)
	}
	expected := path.Join(tmpHome, "vaults")
	if got != expected {
		t.Errorf("GetVaultDir() = %v, expected %v", got, expected)
	}

	// Verify directory exists and has correct permissions
	info, err := os.Stat(got)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if !info.IsDir() {
		t.Errorf("%v is not a directory", got)
	}
	perm := info.Mode().Perm()
	if perm != 0700 {
		t.Errorf("GetVaultDir() permissions = %v, expected 0700", perm)
	}
}

func TestGetTempDir(t *testing.T) {
	Reset()
	tmpRoot := t.TempDir()
	t.Setenv("MRS_TEMP", tmpRoot)

	got, err := GetTempDir()
	if err != nil {
		t.Fatalf("GetTempDir() error = %v", err)
	}

	if !strings.HasPrefix(got, path.Join(tmpRoot, "mrs")) {
		t.Errorf("GetTempDir() = %v, expected it to be inside %v/mrs", got, tmpRoot)
	}

	// Verify directory exists
	info, err := os.Stat(got)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if !info.IsDir() {
		t.Errorf("%v is not a directory", got)
	}
}

func TestEditor(t *testing.T) {
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
			t.Setenv("EDITOR", tt.editor)
			got := Editor()
			if !slices.Equal(got, tt.expected) {
				t.Errorf("Editor() = %q, expected %q", got, tt.expected)
			}
		})
	}
}
