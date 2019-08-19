package main

import (
	"os"

	"github.com/andornaut/mrs/cmd"
	"github.com/andornaut/mrs/internal/fs"
)

// Execute starts the CLI
func main() {
	defer fs.RemoveTempDir()
	if err := cmd.Cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
