package config

import (
	"os"
	"path"
	"strings"
	"sync"
	"unicode"
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

// Editor returns the command to run to launch a text editor, as a program
// followed by its arguments. $EDITOR commonly carries arguments - "vim -n",
// "code -w", "emacsclient -t" - so it is split rather than treated as a single
// program name. Arguments are split on whitespace, honouring single quotes,
// double quotes and backslash escapes, so that a program whose path contains a
// space can be quoted. The editor is executed directly rather than through a
// shell, so no shell metacharacters are interpreted.
func Editor() []string {
	argv := splitArgs(os.Getenv("EDITOR"))
	if len(argv) == 0 {
		return []string{"nano"}
	}
	return argv
}

func splitArgs(s string) []string {
	var (
		argv    []string
		current strings.Builder
		quote   rune
		escaped bool
		started bool
	)
	for _, r := range s {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\' && quote != '\'':
			// A backslash is literal inside single quotes.
			escaped = true
			started = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			started = true
		case unicode.IsSpace(r):
			if started {
				argv = append(argv, current.String())
				current.Reset()
				started = false
			}
		default:
			current.WriteRune(r)
			started = true
		}
	}
	if started {
		argv = append(argv, current.String())
	}
	return argv
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
		// MkdirAll leaves a directory that already exists alone, so a vault
		// directory readable by others - restored from an archive, or made
		// under a permissive umask - has its group and other bits cleared.
		// Only those: setting the mode outright would add write permission to
		// a directory deliberately made read-only. This is best-effort, since
		// a directory mrs may not chmod, or one on a filesystem that has no
		// modes to set, is still usable for storing vaults.
		if fi, statErr := os.Stat(p); statErr == nil {
			_ = os.Chmod(p, fi.Mode().Perm()&^0077)
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

// Reset resets the sync.Once states and variables. This is only used for testing.
func Reset() {
	baseDir = ""
	baseDirErr = nil
	baseDirOnce = sync.Once{}

	tempDir = ""
	tempDirErr = nil
	tempDirOnce = sync.Once{}

	vaultDir = ""
	vaultDirErr = nil
	vaultDirOnce = sync.Once{}
}
