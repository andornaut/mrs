package prompt

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/andornaut/mrs/internal/config"
	"golang.org/x/term"
)

// Bool prompts for input and returns true if the trimmed input was "y"
func Bool(msg string, defaultTrue bool) bool {
	d := "n"
	if defaultTrue {
		d = "y"
	}
	fmt.Printf("%s (y/n) [%s]: ", msg, d)
	answer := scanTrimmedLine()
	if answer == "" {
		return defaultTrue
	}
	return answer == "y"
}

// Editor opens the file at p using a text editor
func Editor(p string) error {
	cmd := exec.Command(config.Editor, p)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = filepath.Dir(p)
	return cmd.Run()
}

// Password prompts the user to enter a password without echoing their input
func Password(msg string) string {
	fmt.Print(msg + ": ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	// Since user input is not echoed, we must add a newline manually
	fmt.Print("\n")
	if err != nil {
		log.Fatalf("Input error: %s\n", err)
	}
	return string(b)

}

// TrimmedLine prompts for input and returns the first line of input as a trimmed string
func TrimmedLine(msg string) string {
	fmt.Print(msg + ": ")
	return scanTrimmedLine()
}

func scanTrimmedLine() string {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	if err := scanner.Err(); err != nil {
		log.Fatalf("Input error: %s\n", err)
	}
	return strings.TrimSpace(scanner.Text())
}
