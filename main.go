package main

import (
	"fmt"
	"os"

	"github.com/andornaut/mrs/cmd"
	"github.com/andornaut/mrs/internal/fs"
)

// Execute starts the CLI
func main() {
	defer func() {
		if err := fs.RemoveTempDir(); err != nil {
			fmt.Fprintf(os.Stderr, "SECURITY WARNING: a directory that contains secrets was not removed: %s\n", err)
		}
	}()
	if err := cmd.Cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
