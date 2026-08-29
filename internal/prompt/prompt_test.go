package prompt

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capturePrompt redirects prompt output to a buffer for the duration of a test
// and returns it. Prompts must never reach stdout, because stdout carries the
// secrets that `export` and `search` write.
func capturePrompt(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := promptOut
	promptOut = &buf
	t.Cleanup(func() { promptOut = prev })
	return &buf
}

// pretendTerminal makes the password prompt believe stdin is a terminal, so
// that the branch which writes the prompt can be reached at all. Reading the
// password afterwards still fails, which is what the caller under test wants.
func pretendTerminal(t *testing.T) {
	t.Helper()
	prev := isTerminal
	isTerminal = func(int) bool { return true }
	t.Cleanup(func() { isTerminal = prev })
}

// withStdin replaces os.Stdin with a file holding the given input.
func withStdin(t *testing.T, input string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(input); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	prev := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = prev; _ = f.Close() })
}

func TestEveryPromptIsWrittenAwayFromStdout(t *testing.T) {
	buf := capturePrompt(t)
	pretendTerminal(t)
	withStdin(t, "a name\n")

	if _, err := Confirm(false, "Delete vault personal?"); err != nil {
		t.Fatalf("Confirm() error: %s", err)
	}
	// The read fails, because the fake terminal is a file. What matters is
	// where the prompt went on the way there.
	_, _ = Password("Vault password")

	for _, want := range []string{
		"Delete vault personal? (y/n) [n]: ",
		"Vault password: ",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("expected %q to be written away from stdout, got %q", want, buf.String())
		}
	}
}

func TestPasswordNeedsATerminal(t *testing.T) {
	capturePrompt(t)
	withStdin(t, "")

	_, err := Password("Vault password")

	if !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("expected ErrNoTerminal, got %v", err)
	}
	// The message has to name what it was asking for, since a caller may be
	// asked for a current password and a new one in the same command.
	if !strings.Contains(err.Error(), "Vault password") {
		t.Errorf("expected the error to name the prompt, got %q", err)
	}
}

// `echo a password > pw` leaves a newline that is not part of the password, so
// trailing newlines are trimmed to match what the prompt returns. Nothing else
// is: a space is a character of the password like any other.
func TestOnlyATrailingNewlineIsTrimmedFromAPasswordFile(t *testing.T) {
	tests := map[string]struct{ contents, want string }{
		"bare":                {"a password", "a password"},
		"unix newline":        {"a password\n", "a password"},
		"windows newline":     {"a password\r\n", "a password"},
		"several":             {"a password\n\n", "a password"},
		"surrounding spaces":  {"  a password  \n", "  a password  "},
		"an interior newline": {"two\nlines\n", "two\nlines"},
	}
	for desc, tt := range tests {
		t.Run(desc, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "pw")
			if err := os.WriteFile(p, []byte(tt.contents), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := readPasswordFile(p)
			if err != nil {
				t.Fatalf("readPasswordFile() error: %s", err)
			}
			if string(got) != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestAMissingPasswordFileIsNamed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "absent")
	_, err := readPasswordFile(p)
	if err == nil {
		t.Fatal("expected an error for a missing password file")
	}
	// The path, not just the phrase: a command may be given two password files,
	// and the one it could not read is the useful half of the answer. Asserted
	// in mrs's own wording, because the error the filesystem returns names the
	// path as well, and a bare substring would pass without mrs naming it.
	want := fmt.Sprintf("password file %q", p)
	if !strings.Contains(err.Error(), want) {
		t.Errorf("expected the error to contain %s, got %q", want, err)
	}
}

// acceptAny stands in for the caller's validator where a test is not about
// what a password has to be.
func acceptAny([]byte) error { return nil }

func TestAPasswordFileSkipsThePromptEntirely(t *testing.T) {
	buf := capturePrompt(t)
	p := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(p, []byte("a password"), 0600); err != nil {
		t.Fatal(err)
	}

	for _, get := range []func(string) ([]byte, error){
		GivenOrPromptPassword,
		func(f string) ([]byte, error) { return GivenOrPromptConfirmedPassword(acceptAny, f) },
		func(f string) ([]byte, error) { return GivenOrPromptNewPassword(acceptAny, f) },
	} {
		got, err := get(p)
		if err != nil {
			t.Fatalf("error: %s", err)
		}
		if string(got) != "a password" {
			t.Errorf("expected the file's password, got %q", got)
		}
	}
	// A supplied password is not confirmed, so nothing is asked at all.
	if buf.Len() != 0 {
		t.Errorf("expected no prompt when a password file is given, got %q", buf.String())
	}
}

// noTerminalToPromptOn points the prompt at a terminal that cannot be opened,
// which is what a process with a terminal on stdin but no controlling terminal
// of its own finds.
func noTerminalToPromptOn(t *testing.T) {
	t.Helper()
	prev := ttyPath
	ttyPath = filepath.Join(t.TempDir(), "no-such-terminal")
	t.Cleanup(func() { ttyPath = prev })
}

// A prompt with nowhere to go is reported, not skipped and not waited on, and
// names the flag that supplies the answer instead.
func TestAPromptWithNoTerminalToWriteOnIsReported(t *testing.T) {
	noTerminalToPromptOn(t)
	pretendTerminal(t)
	withStdin(t, "a password\n")

	if _, err := GivenOrPromptPassword(""); err == nil {
		t.Fatal("expected an error with no terminal to prompt on")
	} else if !errors.Is(err, ErrNoPrompt) {
		t.Errorf("expected ErrNoPrompt, got %q", err)
	} else if !strings.Contains(err.Error(), "--password-file") {
		t.Errorf("expected the error to name --password-file, got %q", err)
	}

	if _, err := Confirm(false, "Delete vault work?"); err == nil {
		t.Fatal("expected an error with no terminal to prompt on")
	} else if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("expected the error to name --yes, got %q", err)
	}
}

// A password read from a file is checked as soon as it is read, so a caller
// that reads one before asking for anything else refuses it before asking.
func TestAPasswordFileIsCheckedWhenItIsRead(t *testing.T) {
	capturePrompt(t)
	p := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(p, []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}
	refuse := func([]byte) error { return errors.New("password is no good") }

	if _, err := GivenOrPromptNewPassword(refuse, p); err == nil {
		t.Fatal("expected the password file to be refused")
	} else if !strings.Contains(err.Error(), "password is no good") {
		t.Errorf("expected the validator's error, got %q", err)
	}
}

func TestTheFlagThatSuppliesAPasswordIsNamed(t *testing.T) {
	capturePrompt(t)
	withStdin(t, "")

	// Which flag applies depends on which password is being asked for, so the
	// prompt itself cannot name it: --password-file supplies a vault's current
	// password and cannot supply the one it is being changed to.
	tests := map[string]struct {
		get  func(string) ([]byte, error)
		flag string
	}{
		"current password": {GivenOrPromptPassword, "--password-file"},
		"a new vault": {
			func(f string) ([]byte, error) { return GivenOrPromptConfirmedPassword(acceptAny, f) },
			"--password-file",
		},
		"changed password": {
			func(f string) ([]byte, error) { return GivenOrPromptNewPassword(acceptAny, f) },
			"--new-password-file",
		},
	}
	for desc, tt := range tests {
		t.Run(desc, func(t *testing.T) {
			_, err := tt.get("")
			if err == nil {
				t.Fatal("expected an error without a terminal")
			}
			if !strings.Contains(err.Error(), tt.flag) {
				t.Errorf("expected the error to name %s, got %q", tt.flag, err)
			}
		})
	}
}

func TestOnlyYesConfirms(t *testing.T) {
	tests := map[string]struct {
		input string
		want  bool
	}{
		"y":                {"y\n", true},
		"n":                {"n\n", false},
		"a bare newline":   {"\n", false},
		"end of input":     {"", false}, // which Ctrl-D gives
		"the whole word":   {"yes\n", false},
		"a capital Y":      {"Y\n", false},
		"y among spaces":   {" y \n", true}, // the answer is trimmed
		"something else":   {"maybe\n", false},
		"y then something": {"y and more\n", false},
	}
	for desc, tt := range tests {
		t.Run(desc, func(t *testing.T) {
			capturePrompt(t)
			pretendTerminal(t)
			withStdin(t, tt.input)
			got, err := Confirm(false, "Continue?")
			if err != nil {
				t.Fatalf("Confirm(%q) error: %s", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("Confirm(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestAConfirmationNeedsATerminalOrAFlag(t *testing.T) {
	buf := capturePrompt(t)
	withStdin(t, "y\n")

	// Nobody is there to answer, so the question is not asked. Taking the safe
	// answer would exit successfully having done nothing, which reads as "done"
	// to the script that ran it.
	_, err := Confirm(false, "Delete vault personal?")
	if !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("expected ErrNoTerminal, got %v", err)
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("expected the error to name --yes, got %q", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no question to be asked, got %q", buf.String())
	}

	// And with the flag, it is answered without being asked.
	got, err := Confirm(true, "Delete vault personal?")
	if err != nil || !got {
		t.Fatalf("Confirm(true, ...) = %v, %v; want true, nil", got, err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no question to be asked, got %q", buf.String())
	}
}
