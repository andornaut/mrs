package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/andornaut/mrs/cmd"
	"github.com/andornaut/mrs/internal/fs"
)

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

	// Handle signals to ensure cleanup on interrupt
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		cleanup()
		os.Exit(1)
	}()

	if err := cmd.Cmd.Execute(); err != nil {
		return 1
	}
	return 0
}
