package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/andornaut/mrs/internal/config"
)

// Prompts are written here rather than to stdout, so that they cannot be
// mistaken for output: `mrs vault export > secrets` and `mrs search key | less`
// both redirect stdout, and a prompt written there would land in the file or
// the pipe instead of in front of the user. It is a variable so that a test can
// capture what was written and to where; only tests reassign it.
var promptOut io.Writer = os.Stderr

// isTerminal reports whether a file descriptor is a terminal. A variable for
// the same reason: without it, the branch that writes the password prompt is
// unreachable from a test, because a test's stdin is never a terminal.
var isTerminal = term.IsTerminal

// Confirm asks msg and reports whether the answer was "y". assumeYes answers it
// without asking, for a caller whose --yes flag was given.
//
// Without a terminal there is nobody to ask, so this reports ErrNoTerminal
// rather than taking the safe answer: a caller that takes it would exit
// successfully having done nothing, which reads as "done" to the script that
// ran it. Only an answer of "y" is yes, so a stray line cannot destroy a vault.
func Confirm(assumeYes bool, msg string) (bool, error) {
	if assumeYes {
		return true, nil
	}
	if !isTerminal(int(os.Stdin.Fd())) {
		return false, fmt.Errorf("cannot ask %q: %w. Use --yes to answer it", msg, ErrNoTerminal)
	}
	_, _ = fmt.Fprintf(promptOut, "%s (y/n) [n]: ", msg)
	answer, err := scanTrimmedLine()
	if err != nil {
		return false, nil
	}
	return answer == "y", nil
}

// Editor opens the file at p using a text editor
func Editor(p string) error {
	argv := config.Editor()
	args := append(append([]string{}, argv[1:]...), p)
	cmd := exec.Command(argv[0], args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = filepath.Dir(p)
	if err := cmd.Run(); err != nil {
		// Name the editor, because the failure is usually a mistyped or unset
		// $EDITOR rather than anything to do with the secrets being edited.
		return fmt.Errorf("editor \"%s\" failed: %w", strings.Join(argv, " "), err)
	}
	return nil
}

// ErrNoTerminal reports that a prompt had nowhere to read from. Callers that
// own a flag which supplies the value non-interactively test for it, so that
// they can name that flag in the error.
var ErrNoTerminal = errors.New("stdin is not a terminal")

// Password prompts the user to enter a password without echoing their input.
// The caller is responsible for wiping the returned slice.
func Password(msg string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	// Switching off echo needs a terminal. Asking for one that is not there
	// makes the terminal driver report EINVAL, which reaches the user as
	// "inappropriate ioctl for device" and names neither the cause nor a remedy.
	if !isTerminal(fd) {
		return nil, fmt.Errorf("cannot prompt for %q: %w", msg, ErrNoTerminal)
	}
	_, _ = fmt.Fprint(promptOut, msg+": ")
	b, err := term.ReadPassword(fd)
	// Since user input is not echoed, we must add a newline manually
	_, _ = fmt.Fprint(promptOut, "\n")
	if err != nil {
		return nil, fmt.Errorf("input error: %w", err)
	}
	return b, nil
}

// TrimmedLine prompts for input and returns the first line of input as a trimmed string
func TrimmedLine(msg string) (string, error) {
	_, _ = fmt.Fprint(promptOut, msg+": ")
	answer, err := scanTrimmedLine()
	if !isTerminal(int(os.Stdin.Fd())) {
		// Input from a pipe is not echoed, so supply the newline that pressing
		// Enter would have written. Without it, whatever mrs prints next
		// continues the prompt's line: "Vault name: Error: no vault name given".
		_, _ = fmt.Fprint(promptOut, "\n")
	}
	return answer, err
}

func scanTrimmedLine() (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("input error: %w", err)
		}
	}
	return strings.TrimSpace(scanner.Text()), nil
}
