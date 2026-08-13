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
		<-c
		cleanup()
		os.Exit(1)
	}()

	cmd.Cmd.Version = version
	return cmd.Execute()
}
