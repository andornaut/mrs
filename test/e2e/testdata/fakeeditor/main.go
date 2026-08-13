// Command fake-editor stands in for $EDITOR in the end-to-end tests. It is a
// real process that mrs execs and that reads and writes the real temporary file
// mrs hands it; its behaviour is scripted through environment variables.
//
//	FAKE_EDITOR_MODE     what to do with the file (default: noop)
//	FAKE_EDITOR_CONTENT  the content used by the replace, append and prepend modes
//	FAKE_EDITOR_CAPTURE  if set, a path to copy the file to before editing it,
//	                     so that a test can assert on what mrs handed the editor
//	FAKE_EDITOR_LOG      if set, a path to append one line per invocation to
//	FAKE_EDITOR_EXIT     the exit code for the fail mode (default: 1)
//	FAKE_EDITOR_STAT     if set, a path to write the edited file's permissions
//	                     and directory to, so that a test can check that the
//	                     decrypted secrets are not exposed while being edited
//	FAKE_EDITOR_READY    if set, a path to create once the file has been read,
//	                     so that a test can wait for the editor to be running
//	FAKE_EDITOR_SLEEP    seconds to sleep in the hang mode (default: 30)
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	os.Exit(run())
}

func run() int {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "fake-editor: expected a file to edit")
		return 2
	}
	// An editor is passed its own arguments first and the file to edit last.
	p := args[len(args)-1]
	if want, ok := os.LookupEnv("FAKE_EDITOR_EXPECT_ARGS"); ok {
		if got := strings.Join(args[:len(args)-1], " "); got != want {
			fmt.Fprintf(os.Stderr, "fake-editor: expected arguments %q, got %q\n", want, got)
			return 2
		}
	}

	if logPath := os.Getenv("FAKE_EDITOR_LOG"); logPath != "" {
		if err := appendLine(logPath, p); err != nil {
			fmt.Fprintf(os.Stderr, "fake-editor: %s\n", err)
			return 2
		}
	}

	b, err := os.ReadFile(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fake-editor: could not read %s: %s\n", p, err)
		return 2
	}
	original := string(b)

	if capture := os.Getenv("FAKE_EDITOR_CAPTURE"); capture != "" {
		if err := os.WriteFile(capture, b, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "fake-editor: could not capture to %s: %s\n", capture, err)
			return 2
		}
	}

	if stat := os.Getenv("FAKE_EDITOR_STAT"); stat != "" {
		if err := writeStat(stat, p); err != nil {
			fmt.Fprintf(os.Stderr, "fake-editor: %s\n", err)
			return 2
		}
	}

	if ready := os.Getenv("FAKE_EDITOR_READY"); ready != "" {
		// Written and renamed into place, because a test waits for this path to
		// exist and then reads it: a plain write creates the file before it
		// holds anything, and a poll landing in between reads nothing.
		if err := signalReady(ready, p); err != nil {
			fmt.Fprintf(os.Stderr, "fake-editor: could not signal readiness: %s\n", err)
			return 2
		}
	}

	content := os.Getenv("FAKE_EDITOR_CONTENT")
	var updated string
	switch mode := os.Getenv("FAKE_EDITOR_MODE"); mode {
	case "", "noop":
		return 0
	case "replace":
		updated = content
	case "append":
		updated = original
		if updated != "" && !strings.HasSuffix(updated, "\n") {
			updated += "\n"
		}
		updated += content
	case "prepend":
		// What an editor whose cursor starts on the first line produces.
		updated = content + original
	case "clear":
		updated = ""
	case "delete":
		// Simulate an editor that removes the file instead of writing it.
		if err := os.Remove(p); err != nil {
			fmt.Fprintf(os.Stderr, "fake-editor: could not remove %s: %s\n", p, err)
			return 2
		}
		return 0
	case "hang":
		// Stand in for an editor the user has left open.
		seconds := 30
		if s := os.Getenv("FAKE_EDITOR_SLEEP"); s != "" {
			if n, err := strconv.Atoi(s); err == nil {
				seconds = n
			}
		}
		time.Sleep(time.Duration(seconds) * time.Second)
		return 0
	case "fail":
		code := 1
		if s := os.Getenv("FAKE_EDITOR_EXIT"); s != "" {
			if n, err := strconv.Atoi(s); err == nil {
				code = n
			}
		}
		fmt.Fprintln(os.Stderr, "fake-editor: failing on purpose")
		return code
	default:
		fmt.Fprintf(os.Stderr, "fake-editor: unknown mode %q\n", mode)
		return 2
	}

	if err := os.WriteFile(p, []byte(updated), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "fake-editor: could not write %s: %s\n", p, err)
		return 2
	}
	return 0
}

// signalReady atomically publishes the path being edited.
func signalReady(out, p string) error {
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, []byte(p), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, out)
}

// writeStat records how exposed the decrypted file is while it is being edited.
func writeStat(out, p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	di, err := os.Stat(filepath.Dir(p))
	if err != nil {
		return err
	}
	return os.WriteFile(out, fmt.Appendf(nil, "file=%04o dir=%04o path=%s\n",
		fi.Mode().Perm(), di.Mode().Perm(), p), 0600)
}

func appendLine(p, line string) error {
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = fmt.Fprintln(f, line)
	return err
}
