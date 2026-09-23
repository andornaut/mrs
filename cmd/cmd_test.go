package cmd

import (
	"fmt"
	"os/exec"
	"testing"
)

// An editor killed by the signal that interrupts mrs reports the status mrs's
// own signal handler would, so the exit status does not depend on which of the
// two reaches os.Exit first.
func TestAnEditorKilledByACaughtSignalExitsAsTheSignalWould(t *testing.T) {
	for _, tt := range []struct {
		sig  string
		want int
	}{
		{"INT", 130},
		{"TERM", 143},
		// Not one mrs catches, so it is an editor that failed.
		{"USR1", exitFailed},
	} {
		err := exec.Command("sh", "-c", "kill -"+tt.sig+" $$").Run()
		if err == nil {
			t.Fatalf("expected sh to be killed by SIG%s", tt.sig)
		}
		if got := ExitCode(fmt.Errorf("editor failed: %w", err)); got != tt.want {
			t.Errorf("ExitCode() for an editor killed by SIG%s = %d, want %d", tt.sig, got, tt.want)
		}
	}
}
