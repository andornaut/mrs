package config

import (
	"os"
	"path"
	"sync"
)

var (
	baseDir     string
	baseDirErr  error
	baseDirOnce sync.Once

	tempDir     string
	tempDirErr  error
	tempDirOnce sync.Once

	vaultDir     string
	vaultDirErr  error
	vaultDirOnce sync.Once
)

// DefaultVaultName is the name of the default vault
var DefaultVaultName = os.Getenv("MRS_DEFAULT_VAULT_NAME")

// Editor returns the command to run to launch a text editor
func Editor() string {
	e := os.Getenv("EDITOR")
	if e != "" {
		return e
	}
	return "nano"
}

// HideEditorInstructions indicates that instructions comments should be omitted from the top of editor sessions
func HideEditorInstructions() bool {
	return os.Getenv("MRS_HIDE_EDITOR_INSTRUCTIONS") != ""
}

// GetBaseDir returns the directory where mrs stores its files
func GetBaseDir() (string, error) {
	baseDirOnce.Do(func() {
		b := os.Getenv("MRS_HOME")
		if b != "" {
			baseDir = b
			return
		}

		dataDir := os.Getenv("XDG_DATA_HOME")
		if dataDir != "" {
			baseDir = path.Join(dataDir, "mrs")
			return
		}

		homeDir, err := os.UserHomeDir()
		if err != nil {
			baseDirErr = err
			return
		}
		baseDir = path.Join(homeDir, ".local/share/mrs")
	})
	return baseDir, baseDirErr
}

// GetVaultDir returns the directory where mrs stores vault files
func GetVaultDir() (string, error) {
	vaultDirOnce.Do(func() {
		base, err := GetBaseDir()
		if err != nil {
			vaultDirErr = err
			return
		}
		p := path.Join(base, "vaults")
		if err := os.MkdirAll(p, 0700); err != nil {
			vaultDirErr = err
			return
		}
		vaultDir = p
	})
	return vaultDir, vaultDirErr
}

// GetTempDir returns the directory where mrs stores temporary files.
// It creates the directory if it does not exist.
func GetTempDir() (string, error) {
	tempDirOnce.Do(func() {
		p := os.Getenv("MRS_TEMP")
		if p == "" {
			p = os.Getenv("XDG_RUNTIME_DIR")
		}
		if p == "" {
			p = os.TempDir()
		}
		p = path.Join(p, "mrs")
		if err := os.MkdirAll(p, 0700); err != nil {
			tempDirErr = err
			return
		}
		p, err := os.MkdirTemp(p, "")
		if err != nil {
			tempDirErr = err
			return
		}
		tempDir = p
	})
	return tempDir, tempDirErr
}
