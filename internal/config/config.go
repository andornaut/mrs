package config

import (
	"io/ioutil"
	"log"
	"os"
	"path"
)

// DefaultVaultName is the name of the default vault
var DefaultVaultName = os.Getenv("MRS_DEFAULT_VAULT_NAME")

// Editor is the command to run to launch a text editor
var Editor = func() string {
	e := os.Getenv("EDITOR")
	if e != "" {
		return e
	}
	return "nano"
}()

// HideEditorInstructions indicates that instructions comments should be omitted from the top of editor sessions
var HideEditorInstructions = os.Getenv("MRS_HIDE_EDITOR_INSTRUCTIONS") != ""

// BaseDir is the directory where mrs stores its files
var BaseDir = func() string {
	b := os.Getenv("MRS_HOME")
	if b != "" {
		return b
	}

	dataDir := os.Getenv("XDG_DATA_HOME")
	if dataDir != "" {
		return path.Join(dataDir, "mrs")
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	return path.Join(homeDir, ".local/share/mrs")
}()

// TempDir is the directory where mrs stores temporary files
var TempDir = createTempDir()

// VaultDir is the directory where mrs stores vault files
var VaultDir = createVaultDir()

func createVaultDir() string {
	p := path.Join(BaseDir, "vaults")
	if err := os.MkdirAll(p, 0700); err != nil {
		log.Fatalf("Could not create vault directory %s: %s\n", p, err)
	}
	return p
}

// createTempDir creates a temp dir and returns its path.
// TempDir is removed on program exit, but we cannot remove the entire ".../mrs" directory without
// interfering with other instances of mrs, so we create an instance-specific temp dir using ioutil.TempDir,
// which means that we have to create the directory as a side-effect of determining its path.
func createTempDir() string {
        p := os.Getenv("MRS_TEMP")
        if p == "" {
                p = os.Getenv("XDG_RUNTIME_DIR")
        }
	if p == "" {
		p = os.TempDir()
	}
	p = path.Join(p, "mrs")
	if err := os.MkdirAll(p, 0700); err != nil {
		log.Fatalf("Could not create temporary directory %s: %s", p, err)
	}
	p, err := ioutil.TempDir(p, "")
	if err != nil {
		log.Fatalf("Could not create temporary directory %s: %s", p, err)
	}
	return p
}
