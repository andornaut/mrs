package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/andornaut/mrs/cmd"
	"github.com/andornaut/mrs/internal/fs"
)

// version is the release this binary was built from. GoReleaser sets it at
// link time; a build made any other way reports "dev".
var version = "dev"

// exitInterrupted is the status for a signal that carries no number to add to
// 128, which os.Interrupt does not on every platform.
const exitInterrupted = 128

func main() {
	os.Exit(run())
}

func run() int {
	// Setup cleanup
	cleanup := func() {
		if err := fs.RemoveTempDir(); err != nil {
			fmt.Fprintf(os.Stderr, "SECURITY WARNING: a directory that contains secrets was not removed: %s\n", err)
		}
	}
	defer cleanup()

	// Handle signals to ensure cleanup on interrupt. SIGHUP matters as much as
	// SIGINT here: it arrives when the terminal running mrs goes away, which a
	// dropped ssh session does while an editor is open holding the decrypted
	// secrets. SIGQUIT is caught for the same reason, and because the core
	// dump it otherwise triggers would itself contain them. SIGKILL cannot be
	// caught, so secrets being edited when one arrives are left in the
	// temporary directory.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		s := <-c
		cleanup()
		// 128+signum, as a shell reports a command its signal killed. mrs
		// gives 1, 2 and 3 meanings of its own, so a run cut short must not
		// exit with any of them: an interrupted search did not finish looking,
		// and is neither a failure nor a search that matched nothing.
		code := exitInterrupted
		if sig, ok := s.(syscall.Signal); ok {
			code = 128 + int(sig)
		}
		os.Exit(code)
	}()

	cmd.Cmd.Version = version
	return cmd.ExitCode(cmd.Cmd.Execute())
}
