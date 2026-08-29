package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Capability 8: decrypted secrets do not outlive the process. Editing writes
// the secrets to a real file in plaintext, so every way mrs can be stopped
// while that file exists has to end with it gone.

// interruptedEdit starts an editing session, waits until the decrypted file is
// on disk, and returns its path along with the running command.
func (l *lab) interruptedEdit(name, pwFile string) (string, *exec.Cmd) {
	l.t.Helper()
	ready := filepath.Join(filepath.Dir(l.Home), "editor-ready")
	cmd := l.hangingEdit(ready, name, pwFile)
	editing := strings.TrimSpace(readFile(l.t, ready))

	// The decrypted secrets are on disk right now, mid-session.
	if !strings.Contains(readFile(l.t, editing), "the-secret-value") {
		l.t.Fatalf("expected the decrypted file at %s to hold the secrets", editing)
	}
	return editing, cmd
}

func TestAnInterruptedEditingSessionLeavesNoPlaintext(t *testing.T) {
	// Every signal that can end mrs while an editor is open: SIGINT is Ctrl-C,
	// SIGHUP a closed terminal or a dropped ssh session, SIGQUIT Ctrl-\, and
	// SIGTERM what a shell shutting down or a service manager sends.
	signals := []struct {
		name string
		sig  syscall.Signal
	}{
		{"SIGINT", syscall.SIGINT},
		{"SIGTERM", syscall.SIGTERM},
		{"SIGHUP", syscall.SIGHUP},
		{"SIGQUIT", syscall.SIGQUIT},
	}
	for _, s := range signals {
		t.Run(s.name, func(t *testing.T) {
			l := newLab(t)
			pwFile := l.seedVault("personal", "a password", "a key\nthe-secret-value\n")
			editing, cmd := l.interruptedEdit("personal", pwFile)

			if err := cmd.Process.Signal(s.sig); err != nil {
				t.Fatalf("failed to signal mrs: %s", err)
			}
			waitForExit(t, cmd)
			// 128+signum, as a shell reports a command its signal killed. A run
			// cut short must not exit 1, 2 or 3, which each say something
			// specific about a run that finished.
			if got, want := cmd.ProcessState.ExitCode(), 128+int(s.sig); got != want {
				t.Fatalf("expected mrs to exit %d after %s, got %d", want, s.name, got)
			}
			// The editor outlives mrs, but it is holding a file that is
			// already gone.
			assertNotExists(t, editing)
			assertNoPlaintextUnder(t, l.Temp, "the-secret-value")

			// The vault itself is untouched by an interrupted session.
			if got := l.export("personal", pwFile); !strings.Contains(got, "the-secret-value") {
				t.Fatalf("expected the vault to be unchanged, got %q", got)
			}
		})
	}
}

func TestAnInterruptedEditingSessionReleasesTheVault(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\nthe-secret-value\n")
	_, cmd := l.interruptedEdit("personal", pwFile)

	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("failed to signal mrs: %s", err)
	}
	waitForExit(t, cmd)

	// A session cut short must not leave the vault locked against the next one,
	// or the user would need --force to get back in.
	l.editorAppends("b key\nb-value\n")
	l.Unsetenv("FAKE_EDITOR_READY")
	l.Unsetenv("FAKE_EDITOR_SLEEP")

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()
	if got := l.export("personal", pwFile); !strings.Contains(got, "b-value") {
		t.Fatalf("expected the later edit to be saved, got %q", got)
	}
}

func TestPlaintextIsRemovedWhenTheEditorFails(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\nthe-secret-value\n")
	l.Setenv("FAKE_EDITOR_MODE", "fail")

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertFailed()

	// An editor that exits non-zero ends the session as a signal does, and
	// leaves the same file behind if nothing removes it.
	assertNoPlaintextUnder(t, l.Temp, "the-secret-value")
}

func TestNoPlaintextIsLeftAfterAnOrdinarySession(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\nthe-secret-value\n")
	l.editorAppends("b key\nb-value\n")

	l.Run("edit", "-v", "personal", "-p", pwFile).AssertOK()
	l.Run("add", "-v", "personal", "-p", pwFile).AssertOK()

	assertNoPlaintextUnder(t, l.Temp, "the-secret-value", "b-value")
	// The vault directory holds ciphertext only.
	assertNoPlaintextUnder(t, l.VaultDir(), "the-secret-value", "b-value")
	// Nor is the directory mrs made for the session left behind empty.
	entries, err := os.ReadDir(filepath.Join(l.Temp, "mrs"))
	if err == nil && len(entries) != 0 {
		t.Fatalf("expected no session directories under %s, got %v", l.Temp, entries)
	}
}
