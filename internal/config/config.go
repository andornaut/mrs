package config

import (
	"os"
	"path"
	"strings"
	"sync"
	"unicode"
)

// The temporary directory is the only one that has to be remembered:
// os.MkdirTemp creates a new directory on every call, so a second caller would
// otherwise get a directory that the cleanup on exit never removes. The other
// two resolve an environment variable and create a directory that may already
// exist, which is the same answer every time it is asked for.
var (
	tempDir     string
	errTempDir  error
	tempDirOnce sync.Once
)

// DefaultVaultName returns the vault named by $MRS_DEFAULT_VAULT_NAME, or the
// empty string. It is read on each call rather than at startup, as every other
// setting here is, so that the environment mrs runs in is the one it reads.
func DefaultVaultName() string {
	return os.Getenv("MRS_DEFAULT_VAULT_NAME")
}

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
	if b := os.Getenv("MRS_HOME"); b != "" {
		return b, nil
	}
	if dataDir := os.Getenv("XDG_DATA_HOME"); dataDir != "" {
		return path.Join(dataDir, "mrs"), nil
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return path.Join(homeDir, ".local/share/mrs"), nil
}

// GetVaultDir returns the directory where mrs stores vault files, creating it
// if it does not exist.
func GetVaultDir() (string, error) {
	base, err := GetBaseDir()
	if err != nil {
		return "", err
	}
	p := path.Join(base, "vaults")
	if err := os.MkdirAll(p, 0700); err != nil {
		return "", err
	}
	// MkdirAll leaves a directory that already exists alone, so a vault
	// directory readable by others - restored from an archive, or made under a
	// permissive umask - has its group and other bits cleared. Only those:
	// setting the mode outright would add write permission to a directory
	// deliberately made read-only. This is best-effort, since a directory mrs
	// may not chmod, or one on a filesystem that has no modes to set, is still
	// usable for storing vaults.
	if fi, statErr := os.Stat(p); statErr == nil {
		_ = os.Chmod(p, fi.Mode().Perm()&^0077)
	}
	return p, nil
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
			errTempDir = err
			return
		}
		p, err := os.MkdirTemp(p, "")
		if err != nil {
			errTempDir = err
			return
		}
		tempDir = p
	})
	return tempDir, errTempDir
}

// Reset forgets the temporary directory, so that the next call creates a new
// one. This is only used for testing.
func Reset() {
	tempDir = ""
	errTempDir = nil
	tempDirOnce = sync.Once{}
}
