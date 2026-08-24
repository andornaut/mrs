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
	"sync"

	"golang.org/x/term"

	"github.com/andornaut/mrs/internal/config"
)

// promptOut is where prompts go when a test captures them. Only tests assign
// it; when it is nil, openPrompt opens the terminal.
var promptOut io.Writer

// openPrompt returns where a prompt is written: the terminal itself.
//
// Not stdout, which carries the secrets that `export` and `search` write, and
// not stderr either: a prompt written there is gone whenever stderr is
// redirected, and `mrs export -v work 2>/dev/null` would sit waiting for a
// password with nothing on screen. sudo, ssh and gpg all write to the terminal
// for this reason. There is no fallback, because a prompt nobody can see is not
// a prompt: mrs asks on the terminal or reports that it cannot ask.
//
// The caller closes what is returned.
func openPrompt() (io.WriteCloser, error) {
	if promptOut != nil {
		return nopWriteCloser{promptOut}, nil
	}
	f, err := os.OpenFile(ttyPath, os.O_WRONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoPrompt, err)
	}
	return f, nil
}

// ttyPath is the terminal a prompt is written to. A variable so that a test can
// point it at a path that cannot be opened; only tests reassign it.
var ttyPath = "/dev/tty"

// ErrNoPrompt reports that there was nowhere to write a prompt: stdin is a
// terminal, but the process has no controlling terminal to ask on. Like
// ErrNoTerminal it means mrs cannot ask, so a caller that owns a flag which
// supplies the value non-interactively names it.
var ErrNoPrompt = errors.New("the terminal could not be opened to write a prompt on")

// nopWriteCloser lets a test's buffer stand in for the terminal, which the
// prompt closes and a buffer cannot.
type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

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
	out, err := openPrompt()
	if err != nil {
		return false, fmt.Errorf("cannot ask %q: %w. Use --yes to answer it", msg, err)
	}
	defer func() { _ = out.Close() }()
	_, _ = fmt.Fprintf(out, "%s (y/n) [n]: ", msg)
	answer, err := scanTrimmedLine()
	if err != nil {
		// Nothing readable is not a yes, and is not a failure either.
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
	out, err := openPrompt()
	if err != nil {
		return nil, fmt.Errorf("cannot prompt for %q: %w", msg, err)
	}
	defer func() { _ = out.Close() }()
	_, _ = fmt.Fprint(out, msg+": ")
	// term.ReadPassword switches echo off and back on again when it returns, so
	// only a run that never returns leaves it off. The state is recorded for
	// RestoreTerminal, which the signal handler calls.
	forget := rememberTerminal(fd)
	b, err := term.ReadPassword(fd)
	forget()
	// Since user input is not echoed, we must add a newline manually
	_, _ = fmt.Fprint(out, "\n")
	if err != nil {
		return nil, fmt.Errorf("input error: %w", err)
	}
	return b, nil
}

// terminalState is the state to put the terminal back into, recorded while a
// prompt has echo switched off. A mutex rather than a channel because
// RestoreTerminal is called from the signal handler while the prompt may still
// be reading.
var (
	terminalMu    sync.Mutex
	terminalFd    int
	terminalState *term.State
)

// rememberTerminal records the terminal's state so that RestoreTerminal can put
// it back, and returns the function that forgets it again. A state that could
// not be read is not recorded, and restoring then does nothing.
func rememberTerminal(fd int) func() {
	state, err := term.GetState(fd)
	if err != nil {
		return func() {}
	}
	terminalMu.Lock()
	terminalFd, terminalState = fd, state
	terminalMu.Unlock()
	return func() {
		terminalMu.Lock()
		terminalState = nil
		terminalMu.Unlock()
	}
}

// RestoreTerminal puts the terminal back the way an open password prompt found
// it, and does nothing when no prompt is open. A prompt switches echo off, and
// a signal that ends mrs while one is open would otherwise leave the shell it
// returns to echoing nothing of what is typed.
func RestoreTerminal() error {
	terminalMu.Lock()
	defer terminalMu.Unlock()
	if terminalState == nil {
		return nil
	}
	state := terminalState
	terminalState = nil
	return term.Restore(terminalFd, state)
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
