package e2e

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
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
	cmd := exec.Command(mrsBin, args...)
	cmd.Env = l.environ()
	cmd.Dir = l.UserHome

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

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		l.t.Fatalf("mrs %v timed out on a terminal; it is probably waiting for input\noutput:\n%s", args, <-out)
	}
	return &ttyResult{t: l.t, Args: args, Output: <-out, ExitCode: cmd.ProcessState.ExitCode()}
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

// AssertOutput asserts that the terminal received the given substring.
func (r *ttyResult) AssertFailed() *ttyResult {
	r.t.Helper()
	if r.ExitCode != 1 {
		r.t.Fatalf("expected exit 1\n%s", r.describe())
	}
	return r
}

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

	l.RunTTY("n\n", "vault", "delete", "personal").
		AssertOK().
		AssertOutput("Delete vault personal? (y/n) [n]: ").
		AssertOutput("Cancelled").
		AssertNoOutput("Deleted vault")
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")

	l.RunTTY("y\n", "vault", "delete", "personal").
		AssertOK().
		AssertOutput("Deleted vault personal").
		AssertNoOutput("Cancelled")
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("")
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

	l.RunTTY("short\n", "vault", "create", "personal").
		AssertFailed().
		AssertOutput("password must contain at least 8 characters").
		AssertNoOutput("Confirm password")
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("")

	// The confirmation is still asked for a password that could be accepted.
	l.RunTTY("a good password\na good password\n", "vault", "create", "personal").
		AssertOK().
		AssertOutput("Confirm password").
		AssertOutput("Created vault personal")
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
	r := l.runTTYWithStderr(stderr, "a password\n", "export", "-v", "personal")
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

// runTTYWithStderr is RunTTY with stderr sent to a file instead of the
// terminal, which is what a caller writing "2> log" does.
func (l *lab) runTTYWithStderr(stderrPath, answer string, args ...string) *ttyResult {
	l.t.Helper()
	f, err := os.Create(stderrPath)
	if err != nil {
		l.t.Fatalf("failed to create %s: %s", stderrPath, err)
	}
	defer func() { _ = f.Close() }()

	cmd := exec.Command(mrsBin, args...)
	cmd.Env = l.environ()
	cmd.Dir = l.UserHome
	cmd.Stderr = f

	tty, err := pty.Start(cmd)
	if err != nil {
		l.t.Fatalf("failed to start mrs %v on a terminal: %s", args, err)
	}
	defer func() { _ = tty.Close() }()

	if _, err := tty.WriteString(answer); err != nil {
		l.t.Fatalf("failed to write %q to the terminal: %s", answer, err)
	}
	out := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, tty)
		out <- buf.String()
	}()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		l.t.Fatalf("mrs %v timed out on a terminal; it is probably waiting for input\noutput:\n%s", args, <-out)
	}
	return &ttyResult{t: l.t, Args: args, Output: <-out, ExitCode: cmd.ProcessState.ExitCode()}
}
