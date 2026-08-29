package e2e

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
)

// Capability 11: the questions mrs asks, answered. Every other test drives mrs
// through a pipe, where there is nobody to ask and a confirmation is reported
// as unanswerable rather than put. These run it on a pseudo-terminal instead,
// which is the only way to reach the answer itself.

// ttyResult is the outcome of a run on a terminal. Its output is one stream,
// because that is what a terminal is: stdout and stderr arrive interleaved, and
// the answer the test typed is echoed back among them.
type ttyResult struct {
	t        *testing.T
	Args     []string
	Output   string
	ExitCode int
}

// RunTTY runs mrs with a pseudo-terminal for its standard streams and answer
// waiting to be read. The answer is written before mrs starts reading, which
// the terminal holds until it does.
func (l *lab) RunTTY(answer string, args ...string) *ttyResult {
	l.t.Helper()
	return l.runTTY(nil, answer, args...)
}

// runTTY is the shared core of RunTTY and runTTYDiverting: configure, when not
// nil, adjusts the command before it is given the terminal.
func (l *lab) runTTY(configure func(*exec.Cmd), answer string, args ...string) *ttyResult {
	l.t.Helper()
	cmd := l.configured(exec.Command(mrsBin, args...))
	if configure != nil {
		configure(cmd)
	}

	f, err := pty.Start(cmd)
	if err != nil {
		l.t.Fatalf("failed to start mrs %v on a terminal: %s", args, err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.WriteString(answer); err != nil {
		l.t.Fatalf("failed to write %q to the terminal: %s", answer, err)
	}

	// Drained in the background, so that mrs cannot block writing to a
	// terminal nobody is reading.
	out := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		// The master side reports EIO rather than EOF once the child is gone,
		// so whatever was read before the error is the whole of the output.
		_, _ = io.Copy(&buf, f)
		out <- buf.String()
	}()

	if !waitOrKill(cmd) {
		l.t.Fatalf("mrs %v timed out on a terminal; it is probably waiting for input\noutput:\n%s", args, <-out)
	}
	return &ttyResult{t: l.t, Args: args, Output: <-out, ExitCode: cmd.ProcessState.ExitCode()}
}

// waitOrKill waits for mrs to end, killing it after 30 seconds so that a run
// that never ends fails in its own test rather than holding the package until
// the test binary's own timeout kills it ten minutes later. It reports whether
// mrs ended on its own, so the caller fails with what only it knows.
func waitOrKill(cmd *exec.Cmd) bool {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		return true
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return false
	}
}

func (r *ttyResult) describe() string {
	return fmt.Sprintf("mrs %s\nexit: %d\noutput:\n%s", strings.Join(r.Args, " "), r.ExitCode, r.Output)
}

// AssertOK asserts that mrs exited successfully.
func (r *ttyResult) AssertOK() *ttyResult {
	r.t.Helper()
	if r.ExitCode != 0 {
		r.t.Fatalf("expected success, got exit %d\n%s", r.ExitCode, r.describe())
	}
	return r
}

// AssertFailed asserts the status mrs gives a command that ran and failed.
func (r *ttyResult) AssertFailed() *ttyResult {
	r.t.Helper()
	if r.ExitCode != 1 {
		r.t.Fatalf("expected exit 1\n%s", r.describe())
	}
	return r
}

// AssertOutput asserts that the terminal received the given substring.
func (r *ttyResult) AssertOutput(want string) *ttyResult {
	r.t.Helper()
	if !strings.Contains(r.Output, want) {
		r.t.Fatalf("expected the terminal to show %q\n%s", want, r.describe())
	}
	return r
}

// AssertNoOutput asserts that the terminal received no such substring.
func (r *ttyResult) AssertNoOutput(unwanted string) *ttyResult {
	r.t.Helper()
	if strings.Contains(r.Output, unwanted) {
		r.t.Fatalf("expected the terminal not to show %q\n%s", unwanted, r.describe())
	}
	return r
}

// Declining is a normal outcome, so mrs says so and exits 0. Answering "y" is
// tested alongside it, because a Confirm that always answered no would satisfy
// the first half on its own.
func TestDeleteIsCancelledByAnAnswerOfNo(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	l.RunTTY("n\n", "vault", "rm", "personal").
		AssertOK().
		AssertOutput("Delete vault personal? (y/n) [n]: ").
		AssertOutput("Cancelled").
		AssertNoOutput("Deleted vault")
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("personal")

	l.RunTTY("y\n", "vault", "rm", "personal").
		AssertOK().
		AssertOutput("Deleted vault personal").
		AssertNoOutput("Cancelled")
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("")
}

func TestEmptyingAVaultIsCancelledByAnAnswerOfNo(t *testing.T) {
	l := newLab(t)
	contents := "a key\na value\n\nb key\nb value\n"
	pwFile := l.seedVault("personal", "a password", contents)
	l.Setenv("FAKE_EDITOR_MODE", "clear")

	l.RunTTY("n\n", "edit", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertOutput("This will remove all 2 secrets from vault personal. Continue? (y/n) [n]: ").
		AssertOutput("Cancelled").
		AssertNoOutput("Saved changes")
	l.Run("export", "-v", "personal", "-p", pwFile).AssertOK().AssertStdoutExactly(contents)

	l.RunTTY("y\n", "edit", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertOutput("Saved changes to vault personal").
		AssertNoOutput("Cancelled")
	l.Run("export", "-v", "personal", "-p", pwFile).AssertOK().AssertStdoutEquals("")
}

// A password mrs will not accept is refused after one entry rather than after
// two: nothing asks the user to confirm a password it has already rejected.
func TestATypedPasswordIsCheckedBeforeItIsConfirmed(t *testing.T) {
	l := newLab(t)

	l.RunTTY("short\n", "vault", "add", "personal").
		AssertFailed().
		AssertOutput("password must contain at least 8 characters").
		AssertNoOutput("Confirm password")
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("")

	// The confirmation is still asked for a password that could be accepted.
	l.RunTTY("a good password\na good password\n", "vault", "add", "personal").
		AssertOK().
		AssertOutput("Confirm password").
		AssertOutput("Created vault personal")
}

// A password is typed twice and the two must agree: a typo would otherwise
// encrypt the vault under a password its owner does not know.
func TestTwoTypedPasswordsThatDisagreeAreRefused(t *testing.T) {
	l := newLab(t)

	l.RunTTY("a good password\na different password\n", "vault", "add", "personal").
		AssertFailed().
		AssertOutput("Confirm password").
		AssertOutput("password mismatch").
		AssertNoOutput("Created vault")
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("")
}

// change-password asks for two passwords, so the one it refused is named.
func TestARefusedNewPasswordIsNamed(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	l.RunTTY("a password\nshort\n", "vault", "change-password", "personal").
		AssertFailed().
		AssertOutput("invalid new password: password must contain at least 8 characters").
		AssertNoOutput("Confirm password")
}

// Prompts go to the terminal, not to stderr: redirecting stderr must not leave
// mrs waiting for a password with nothing on screen.
func TestPromptsGoToTheTerminalNotToStderr(t *testing.T) {
	l := newLab(t)
	l.seedVault("personal", "a password", "a key\na value\n")

	stderr := filepath.Join(l.UserHome, "stderr")
	r := l.runTTYDiverting(divertStderr, stderr, "a password\n", "export", "-v", "personal")
	r.AssertOK()
	if !strings.Contains(r.Output, "Vault password") {
		t.Errorf("expected the prompt on the terminal, got %q", r.describe())
	}
	if got := readFile(t, stderr); strings.Contains(got, "Vault password") {
		t.Errorf("expected no prompt on stderr, got %q", got)
	}
	// The secrets still reach stdout, which the terminal carries here.
	if !strings.Contains(r.Output, "a value") {
		t.Errorf("expected the secrets on stdout, got %q", r.describe())
	}
}

// runTTYDiverting runs mrs on a terminal with one of its output streams sent
// to a file instead, which is what a caller writing "2> log" or "> log" does.
// divert is handed the command and the file, and wires up the one it is about.
func (l *lab) runTTYDiverting(divert func(*exec.Cmd, *os.File), path, answer string, args ...string) *ttyResult {
	l.t.Helper()
	f, err := os.Create(path)
	if err != nil {
		l.t.Fatalf("failed to create %s: %s", path, err)
	}
	defer func() { _ = f.Close() }()

	return l.runTTY(func(cmd *exec.Cmd) { divert(cmd, f) }, answer, args...)
}

func divertStdout(cmd *exec.Cmd, f *os.File) { cmd.Stdout = f }
func divertStderr(cmd *exec.Cmd, f *os.File) { cmd.Stderr = f }

// An editor draws its screen on the terminal, not on whatever stdout was
// redirected to. Without this, `mrs edit > log` puts the editor's screen in the
// log and hands the editor a stdout that is not a terminal, which the default
// editor refuses outright.
func TestTheEditorIsGivenTheTerminalNotARedirectedStdout(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")
	// An editor that writes to its own stdout and changes nothing, so that
	// where those bytes land is the whole of what this test is about.
	l.Setenv("EDITOR", "sh -c 'echo EDITOR-DREW-THIS'")

	log := filepath.Join(l.UserHome, "log")
	r := l.runTTYDiverting(divertStdout, log, "", "edit", "-v", "personal", "-p", pwFile)
	r.AssertOK()

	if got := readFile(t, log); strings.Contains(got, "EDITOR-DREW-THIS") {
		t.Errorf("the editor drew into the redirected stdout: %q", got)
	}
	if !strings.Contains(r.Output, "EDITOR-DREW-THIS") {
		t.Errorf("expected the editor's output on the terminal, got %q", r.Output)
	}
}

// A password prompt switches echo off, and a signal that ends mrs while one is
// open must put it back: the shell mrs returns to would otherwise echo nothing
// of what is typed.
func TestASignalAtThePasswordPromptRestoresTheTerminal(t *testing.T) {
	l := newLab(t)
	l.seedVault("personal", "a password", "a key\na value\n")

	for _, tt := range []struct {
		name string
		sig  syscall.Signal
		code int
	}{
		{"SIGINT", syscall.SIGINT, 130},
		{"SIGTERM", syscall.SIGTERM, 143},
		{"SIGHUP", syscall.SIGHUP, 129},
		{"SIGQUIT", syscall.SIGQUIT, 131},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// The terminal is opened before mrs is started, so that its
			// settings are read as they were before a prompt could change
			// them. Starting first and reading afterwards races the prompt.
			ptmx, tty, err := pty.Open()
			if err != nil {
				t.Fatalf("failed to open a terminal: %s", err)
			}
			defer func() { _ = ptmx.Close() }()
			// The two ends of a pty share one set of terminal settings, so the
			// master sees what mrs does to the terminal from the other side.
			fd := int(ptmx.Fd())
			before := terminalState(t, fd)

			cmd := l.configured(exec.Command(mrsBin, "export", "-v", "personal"))
			cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
			if err := cmd.Start(); err != nil {
				t.Fatalf("failed to start mrs on a terminal: %s", err)
			}
			// Closed here, so that the master sees the child go.
			_ = tty.Close()

			// Drained in the background, so that mrs cannot block writing to a
			// terminal nobody is reading, as RunTTY drains it for the same
			// reason. Reading the settings is an ioctl and does not compete
			// with the bytes being read here.
			go func() { _, _ = io.Copy(io.Discard, ptmx) }()

			// Wait for the prompt, which is where the settings change.
			waitForTerminalState(t, fd, func(s string) bool { return s != before })
			if err := cmd.Process.Signal(tt.sig); err != nil {
				t.Fatalf("failed to signal mrs: %s", err)
			}
			waitForExit(t, cmd)
			if got := cmd.ProcessState.ExitCode(); got != tt.code {
				t.Errorf("expected exit %d, got %d", tt.code, got)
			}
			waitForTerminalState(t, fd, func(s string) bool { return s == before })
		})
	}
}

// waitForExit waits for a signalled mrs to end.
func waitForExit(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if !waitOrKill(cmd) {
		t.Fatal("mrs did not exit after the signal")
	}
}

// terminalState returns the terminal's settings in a form that can be compared.
// term.State holds them in an opaque struct, so it is rendered rather than
// examined: the test asks whether they came back, not which of them changed.
func terminalState(t *testing.T, fd int) string {
	t.Helper()
	state, err := term.GetState(fd)
	if err != nil {
		t.Fatalf("failed to read the terminal state: %s", err)
	}
	return fmt.Sprintf("%+v", *state)
}

// waitForTerminalState waits for the terminal's settings to satisfy want.
// Polled, because mrs changes them in its own time and there is nothing to wait
// on but the terminal itself.
func waitForTerminalState(t *testing.T, fd int, want func(string) bool) {
	t.Helper()
	waitFor(t, 10*time.Second, func() bool { return want(terminalState(t, fd)) },
		"the terminal settings did not reach the expected state")
}
