package config

import (
	"os"
	"path"
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
			reset()
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
	reset()
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
	reset()
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
	t.Run("Default editor", func(t *testing.T) {
		t.Setenv("EDITOR", "")
		if got := Editor(); got != "nano" {
			t.Errorf("Editor() = %v, expected nano", got)
		}
	})

	t.Run("Custom editor", func(t *testing.T) {
		t.Setenv("EDITOR", "vim")
		if got := Editor(); got != "vim" {
			t.Errorf("Editor() = %v, expected vim", got)
		}
	})
}
