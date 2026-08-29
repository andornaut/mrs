package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
)

// The temporary directory is the only one that has to be remembered:
// os.MkdirTemp creates a new directory on every call, so a second caller would
// otherwise get a directory that the cleanup on exit never removes. The others
// resolve an environment variable (GetVaultDir also creating a directory that
// may already exist), which is the same answer every time it is asked for.
//
// A mutex rather than a sync.Once, because CreatedTempDir has to read what was
// remembered without asking for a directory to be created. The signal handler
// reads it while the command may still be inside GetTempDir.
var (
	tempDirMu   sync.Mutex
	tempDir     string
	errTempDir  error
	tempDirDone bool
)

// DefaultVaultName returns the vault named by $MRS_DEFAULT_VAULT_NAME, or the
// empty string. It is read on each call rather than at startup, as every other
// setting here is, so that the environment mrs runs in is the one it reads.
func DefaultVaultName() string {
	return os.Getenv("MRS_DEFAULT_VAULT_NAME")
}

// fallbackEditors are the editors to fall back on when neither $VISUAL nor
// $EDITOR names one, in the order they are tried. The first that is on PATH is
// the one that runs.
var fallbackEditors = []string{"vim", "vi", "nano"}

// lookPath is the test seam for finding a fallback editor on PATH.
var lookPath = exec.LookPath

// Editor returns the command to run to launch a text editor, as a program
// followed by its arguments: $VISUAL, else $EDITOR, else the first of
// fallbackEditors that is on PATH. $VISUAL is read first because that is the
// order git, crontab and sudoedit read them in, and an editor chosen for one of
// those is the editor a user expects here.
//
// Either variable commonly carries arguments - "vim -n", "code -w",
// "emacsclient -t" - so it is split rather than treated as a single program
// name. Arguments are split on whitespace, honouring single quotes, double
// quotes and backslash escapes, so that a program whose path contains a space
// can be quoted. The editor is executed directly rather than through a shell,
// so no shell metacharacters are interpreted.
func Editor() []string {
	for _, name := range []string{"VISUAL", "EDITOR"} {
		if argv := splitArgs(os.Getenv(name)); len(argv) > 0 {
			return argv
		}
	}
	for _, name := range fallbackEditors {
		if _, err := lookPath(name); err == nil {
			return []string{name}
		}
	}
	// Nothing on PATH: name the first fallback anyway, so that the failure the
	// user is shown is an editor that could not be run rather than an empty
	// command.
	return []string{fallbackEditors[0]}
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

// baseDir returns the directory where mrs stores its files
func baseDir() (string, error) {
	if b := os.Getenv("MRS_HOME"); b != "" {
		return b, nil
	}
	if dataDir := os.Getenv("XDG_DATA_HOME"); dataDir != "" {
		return filepath.Join(dataDir, "mrs"), nil
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".local/share/mrs"), nil
}

// VaultDir returns the directory where mrs stores vault files, without
// creating it. For a caller that only asks where the directory is, such as one
// deciding how to name a vault in a report, creating it would be a side effect.
func VaultDir() (string, error) {
	base, err := baseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "vaults"), nil
}

// GetVaultDir returns the directory where mrs stores vault files, creating it
// if it does not exist.
func GetVaultDir() (string, error) {
	p, err := VaultDir()
	if err != nil {
		return "", err
	}
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
	tempDirMu.Lock()
	defer tempDirMu.Unlock()
	if tempDirDone {
		return tempDir, errTempDir
	}
	tempDirDone = true

	p := os.Getenv("MRS_TEMP")
	if p == "" {
		p = os.Getenv("XDG_RUNTIME_DIR")
	}
	if p == "" {
		p = os.TempDir()
	}
	p = filepath.Join(p, "mrs")
	if err := os.MkdirAll(p, 0700); err != nil {
		errTempDir = err
		return "", errTempDir
	}
	p, err := os.MkdirTemp(p, "")
	if err != nil {
		errTempDir = err
		return "", errTempDir
	}
	tempDir = p
	return tempDir, nil
}

// CreatedTempDir returns the temporary directory this run created, or the empty
// string if it never created one. Cleanup asks for this rather than for
// GetTempDir, which creates: a run that decrypts nothing would otherwise make a
// directory only to remove it, and a run whose directory could not be made
// would be reported as having left secrets behind.
func CreatedTempDir() string {
	tempDirMu.Lock()
	defer tempDirMu.Unlock()
	return tempDir
}

// Reset forgets the temporary directory, so that the next call creates a new
// one. This is only used for testing.
func Reset() {
	tempDirMu.Lock()
	defer tempDirMu.Unlock()
	tempDir = ""
	errTempDir = nil
	tempDirDone = false
}
