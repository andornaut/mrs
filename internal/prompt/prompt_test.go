package prompt

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capturePrompt redirects prompt output to a buffer for the duration of a test
// and returns it. Prompts must never reach stdout, because stdout carries the
// secrets that `vault export` and `search` write.
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

// withStdin replaces os.Stdin with a pipe holding the given input.
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

func TestPasswordPromptIsNotWrittenToStdout(t *testing.T) {
	buf := capturePrompt(t)
	pretendTerminal(t)
	withStdin(t, "")

	// The read fails, because the fake terminal is a file. What matters is
	// where the prompt went on the way there.
	_, _ = Password("Vault password")

	if !strings.Contains(buf.String(), "Vault password: ") {
		t.Errorf("expected the prompt to be written away from stdout, got %q", buf.String())
	}
}

func TestEveryPromptIsWrittenAwayFromStdout(t *testing.T) {
	buf := capturePrompt(t)
	pretendTerminal(t)
	withStdin(t, "a name\n")

	if _, err := TrimmedLine("Vault name"); err != nil {
		t.Fatalf("TrimmedLine() error: %s", err)
	}
	if _, err := Confirm(false, "Delete vault personal?"); err != nil {
		t.Fatalf("Confirm() error: %s", err)
	}

	for _, want := range []string{"Vault name: ", "Delete vault personal? (y/n) [n]: "} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("expected %q to be written away from stdout, got %q", want, buf.String())
		}
	}
}

func TestALinePromptEndsItsLineWhenInputIsNotEchoed(t *testing.T) {
	buf := capturePrompt(t)
	withStdin(t, "\n")

	// A pipe echoes nothing, so mrs writes the newline that pressing Enter
	// would have. Without it, the next thing written continues this line.
	if _, err := TrimmedLine("Vault name"); err != nil {
		t.Fatalf("TrimmedLine() error: %s", err)
	}
	if got := buf.String(); got != "Vault name: \n" {
		t.Errorf("expected the prompt to end its line, got %q", got)
	}

	// A terminal echoes it already, so mrs must not write a second one.
	buf = capturePrompt(t)
	pretendTerminal(t)
	withStdin(t, "\n")
	if _, err := TrimmedLine("Vault name"); err != nil {
		t.Fatalf("TrimmedLine() error: %s", err)
	}
	if got := buf.String(); got != "Vault name: " {
		t.Errorf("expected no added newline on a terminal, got %q", got)
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

func TestAPasswordFileIsTrimmedOfItsTrailingNewline(t *testing.T) {
	tests := map[string]string{
		"bare":            "a password",
		"unix newline":    "a password\n",
		"windows newline": "a password\r\n",
		"several":         "a password\n\n",
	}
	for desc, contents := range tests {
		t.Run(desc, func(t *testing.T) {
			// `echo a password > pw` leaves a newline that is not part of the
			// password, so it is trimmed to match what the prompt returns.
			p := filepath.Join(t.TempDir(), "pw")
			if err := os.WriteFile(p, []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := readPasswordFile(p)
			if err != nil {
				t.Fatalf("readPasswordFile() error: %s", err)
			}
			if string(got) != "a password" {
				t.Errorf("expected %q, got %q", "a password", got)
			}
		})
	}
}

func TestAPasswordFileKeepsItsInteriorWhitespace(t *testing.T) {
	// Only trailing newlines are trimmed. Spaces are part of the password.
	p := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(p, []byte("  a password  \n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readPasswordFile(p)
	if err != nil {
		t.Fatalf("readPasswordFile() error: %s", err)
	}
	if string(got) != "  a password  " {
		t.Errorf("expected interior whitespace to be kept, got %q", got)
	}
}

func TestAMissingPasswordFileIsNamed(t *testing.T) {
	_, err := readPasswordFile(filepath.Join(t.TempDir(), "absent"))
	if err == nil {
		t.Fatal("expected an error for a missing password file")
	}
	if !strings.Contains(err.Error(), "password file") {
		t.Errorf("expected the error to say which file, got %q", err)
	}
}

func TestAPasswordFileSkipsThePromptEntirely(t *testing.T) {
	buf := capturePrompt(t)
	p := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(p, []byte("a password"), 0600); err != nil {
		t.Fatal(err)
	}

	for _, get := range []func(string) ([]byte, error){
		GivenOrPromptPassword, GivenOrPromptConfirmedPassword, GivenOrPromptNewPassword,
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
		"a new vault":      {GivenOrPromptConfirmedPassword, "--password-file"},
		"changed password": {GivenOrPromptNewPassword, "--new-password-file"},
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

func TestPromptNameRejectsAnEmptyAnswer(t *testing.T) {
	capturePrompt(t)
	withStdin(t, "\n")

	_, err := PromptName()

	if err == nil {
		t.Fatal("expected an error when no name is given")
	}
	// "vault name cannot be empty" described the internal check; this names
	// the flag that supplies one.
	if !strings.Contains(err.Error(), "--vault") {
		t.Errorf("expected the error to name --vault, got %q", err)
	}
}

func TestGivenOrPromptNameReturnsWhatWasGiven(t *testing.T) {
	capturePrompt(t)
	got, err := GivenOrPromptName("personal")
	if err != nil {
		t.Fatalf("GivenOrPromptName() error: %s", err)
	}
	if got != "personal" {
		t.Errorf("expected %q, got %q", "personal", got)
	}
}

func TestOnlyYesConfirms(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"y\n", true},
		{"n\n", false},
		{"\n", false},    // a bare newline is not an answer
		{"", false},      // nor is end-of-input, which Ctrl-D gives
		{"yes\n", false}, // only an exact "y" is yes
		{"Y\n", false},
		{" y \n", true}, // the answer is trimmed
	}
	for _, tt := range tests {
		input, want := tt.input, tt.want
		capturePrompt(t)
		pretendTerminal(t)
		withStdin(t, input)
		got, err := Confirm(false, "Continue?")
		if err != nil {
			t.Fatalf("Confirm(%q) error: %s", input, err)
		}
		if got != want {
			t.Errorf("Confirm(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestAConfirmationNeedsATerminalOrAFlag(t *testing.T) {
	buf := capturePrompt(t)
	withStdin(t, "y\n")

	// Nobody is there to answer, so the question is not asked. Taking the safe
	// answer instead would exit successfully having done nothing, which reads
	// as "done" to the script that ran it.
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
