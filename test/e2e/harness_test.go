// Package e2e exercises the real mrs binary end-to-end: a compiled executable,
// a real filesystem, real encryption and a real editor process. Nothing here is
// mocked or stubbed; every test drives mrs the way a user or a script would.
package e2e

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	// mrsBin is the path to the mrs binary under test.
	mrsBin string
	// editorBin is the path to the scriptable fake editor.
	editorBin string
)

// TestMain builds the binary under test and the fake editor once, so that every
// test runs against a real executable rather than in-process code.
func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	buildDir, err := os.MkdirTemp("", "mrs-e2e-build")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create build dir: %s\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(buildDir) }()

	mrsBin = filepath.Join(buildDir, "mrs")
	if err := build(mrsBin, "../.."); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build mrs: %s\n", err)
		return 1
	}
	editorBin = filepath.Join(buildDir, "fake-editor")
	if err := build(editorBin, "./testdata/fakeeditor"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build fake editor: %s\n", err)
		return 1
	}
	return m.Run()
}

// These tests exercise a binary they compile themselves rather than code they
// import, so nothing tells the go command that a change to mrs invalidates a
// previous run: edit internal/vault, run the suite, and it answers with a stale
// "ok (cached)" for a binary it never built. Reading the module's source from
// inside a test is what stops that. The go command records the files a test
// reads and re-runs the package when any of them changes, so a run that would
// build a different binary is never answered from the cache, while a run that
// would build the same one still is.
//
// It has to be read from a test rather than from TestMain, which is where this
// used to be and where it did nothing: the go command only records what is read
// once testing.M.Run has started.
func TestTheModuleSourceIsRead(t *testing.T) {
	n, err := readModuleSource("../..")
	if err != nil {
		t.Fatalf("failed to read the module source: %s", err)
	}
	// A walk that quietly found nothing - a moved package, a changed layout -
	// would restore caching, and with it the stale pass this exists to prevent.
	if n < 10 {
		t.Fatalf("expected the module's source files to be read, got %d", n)
	}
}

// readModuleSource opens every source file in the module and reports how many
// it read.
func readModuleSource(dir string) (int, error) {
	// Opened through a root so that each file is reached by a path relative to
	// the tree being read, rather than by the absolute one the walk hands back
	// after having already stat'd it.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, err
	}
	defer func() { _ = root.Close() }()

	var n int
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasSuffix(p, ".go"), d.Name() == "go.mod", d.Name() == "go.sum":
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			f, err := root.Open(rel)
			if err != nil {
				return err
			}
			n++
			return f.Close()
		}
		return nil
	})
	return n, err
}

func build(out, pkg string) error {
	cmd := exec.Command("go", "build", "-o", out, pkg)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, stderr.String())
	}
	return nil
}

// lab is an isolated installation of mrs: its own vault directory, temporary
// directory, home directory and environment.
type lab struct {
	t        *testing.T
	Home     string // MRS_HOME
	Temp     string // MRS_TEMP
	UserHome string // HOME
	Env      map[string]string
}

// newLab returns an isolated installation of mrs backed by real directories.
// Each lab has its own directories and environment and drives mrs as a
// subprocess, so tests share nothing and run in parallel, which matters because
// every command derives a key with 600,000 PBKDF2 iterations by design.
func newLab(t *testing.T) *lab {
	t.Helper()
	t.Parallel()
	root := t.TempDir()
	l := &lab{
		t:        t,
		Home:     filepath.Join(root, "mrs-home"),
		Temp:     filepath.Join(root, "mrs-temp"),
		UserHome: filepath.Join(root, "user-home"),
		Env:      map[string]string{},
	}
	for _, d := range []string{l.Home, l.Temp, l.UserHome} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatalf("failed to create %s: %s", d, err)
		}
	}
	// Every variable mrs reads lives in Env, including the ones that point it
	// at the lab's directories, so that a test can unset one and exercise what
	// mrs falls back to.
	l.Env["MRS_HOME"] = l.Home
	l.Env["MRS_TEMP"] = l.Temp
	l.Env["HOME"] = l.UserHome
	l.Env["PATH"] = os.Getenv("PATH")
	// Keep editor sessions non-interactive by default: a test that wants to
	// drive the editor sets the fake editor's mode explicitly.
	l.Env["EDITOR"] = editorBin
	l.Env["FAKE_EDITOR_MODE"] = "noop"
	return l
}

// VaultDir returns the directory in which mrs stores vault files.
func (l *lab) VaultDir() string { return filepath.Join(l.Home, "vaults") }

// Setenv sets an environment variable for every subsequent mrs invocation.
func (l *lab) Setenv(k, v string) { l.Env[k] = v }

// Unsetenv removes an environment variable from every subsequent mrs
// invocation, so that a test can exercise what mrs does without it.
func (l *lab) Unsetenv(k string) { delete(l.Env, k) }

// WriteFile writes a file inside the lab's root and returns its path.
func (l *lab) WriteFile(name, content string) string {
	l.t.Helper()
	p := filepath.Join(filepath.Dir(l.Home), name)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		l.t.Fatalf("failed to create dir for %s: %s", p, err)
	}
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		l.t.Fatalf("failed to write %s: %s", p, err)
	}
	return p
}

// PasswordFile writes a password file and returns its path.
func (l *lab) PasswordFile(name, password string) string {
	return l.WriteFile(name, password)
}

func (l *lab) environ() []string {
	env := make([]string, 0, len(l.Env))
	for k, v := range l.Env {
		env = append(env, k+"="+v)
	}
	return env
}

// result is the observable outcome of running mrs: what a shell would see.
type result struct {
	t        *testing.T
	Args     []string
	Stdout   string
	Stderr   string
	ExitCode int
}

// Run executes mrs with the given arguments and no stdin.
func (l *lab) Run(args ...string) *result {
	l.t.Helper()
	return l.RunStdin("", args...)
}

// RunStdin executes mrs with the given arguments, feeding stdin from a pipe.
// A pipe is not a terminal, which is exactly what a scripted caller has.
func (l *lab) RunStdin(stdin string, args ...string) *result {
	l.t.Helper()
	cmd := exec.Command(mrsBin, args...)
	cmd.Env = l.environ()
	cmd.Dir = l.UserHome
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		l.t.Fatalf("failed to start mrs %v: %s", args, err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		l.t.Fatalf("mrs %v timed out; it is probably waiting for input\nstdout:\n%s\nstderr:\n%s",
			args, stdout.String(), stderr.String())
	}
	return &result{
		t:        l.t,
		Args:     args,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: cmd.ProcessState.ExitCode(),
	}
}

// Start launches mrs without waiting for it, so that a test can interrupt it
// mid-session. Its output goes nowhere, so that waiting for it does not block
// on an editor that outlives it.
func (l *lab) Start(args ...string) *exec.Cmd {
	l.t.Helper()
	cmd := exec.Command(mrsBin, args...)
	cmd.Env = l.environ()
	cmd.Dir = l.UserHome
	if err := cmd.Start(); err != nil {
		l.t.Fatalf("failed to start mrs %v: %s", args, err)
	}
	return cmd
}

// waitForFile waits for a path to appear, which is how a test knows the fake
// editor is running.
func waitForFile(t *testing.T, p string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(p); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", p)
}

// Vaults returns the base names of the files in the vault directory, so that
// tests can assert on what mrs actually left on disk.
func (l *lab) Vaults() []string {
	l.t.Helper()
	entries, err := os.ReadDir(l.VaultDir())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		l.t.Fatalf("failed to read vault dir: %s", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// VaultPath returns the path of the single vault file whose name matches, and
// fails the test if there is not exactly one.
func (l *lab) VaultPath(name string) string {
	l.t.Helper()
	matches, err := filepath.Glob(filepath.Join(l.VaultDir(), name+".*"))
	if err != nil {
		l.t.Fatalf("failed to glob for vault %s: %s", name, err)
	}
	vaults := make([]string, 0, len(matches))
	for _, m := range matches {
		switch filepath.Ext(m) {
		case ".lock", ".bak", ".tmp":
			continue
		}
		vaults = append(vaults, m)
	}
	if len(vaults) != 1 {
		l.t.Fatalf("expected exactly 1 vault file for %s, found %v (all files: %v)", name, vaults, l.Vaults())
	}
	return vaults[0]
}

// createVault creates a vault non-interactively and returns its password file.
func (l *lab) createVault(name, password string) string {
	l.t.Helper()
	pwFile := l.PasswordFile(name+".pw", password)
	l.Run("vault", "add", name, "-p", pwFile).AssertOK()
	return pwFile
}

// seedVault creates a vault whose contents are the given secrets text.
func (l *lab) seedVault(name, password, contents string) string {
	l.t.Helper()
	pwFile := l.PasswordFile(name+".pw", password)
	importFile := l.WriteFile(name+".import", contents)
	l.Run("vault", "add", name, "-p", pwFile, "-i", importFile).AssertOK()
	return pwFile
}

// editorWrites makes the next editor session replace the file with content.
func (l *lab) editorWrites(content string) {
	l.Setenv("FAKE_EDITOR_MODE", "replace")
	l.Setenv("FAKE_EDITOR_CONTENT", content)
}

// editorAppends makes the next editor session append content to the file.
func (l *lab) editorAppends(content string) {
	l.Setenv("FAKE_EDITOR_MODE", "append")
	l.Setenv("FAKE_EDITOR_CONTENT", content)
}

// captureEditorInput makes the next editor session save a copy of what mrs
// handed it, and returns a function that reads that copy.
func (l *lab) captureEditorInput() func() string {
	l.t.Helper()
	p := filepath.Join(filepath.Dir(l.Home), "editor-input")
	l.Setenv("FAKE_EDITOR_CAPTURE", p)
	return func() string { return readFile(l.t, p) }
}

// export returns a vault's decrypted contents.
func (l *lab) export(name, pwFile string) string {
	l.t.Helper()
	return l.Run("export", "-v", name, "-p", pwFile).AssertOK().Stdout
}

func (r *result) describe() string {
	return fmt.Sprintf("mrs %s\nexit: %d\nstdout:\n%s\nstderr:\n%s",
		strings.Join(r.Args, " "), r.ExitCode, r.Stdout, r.Stderr)
}

// AssertOK asserts that mrs exited successfully.
func (r *result) AssertOK() *result {
	r.t.Helper()
	if r.ExitCode != 0 {
		r.t.Fatalf("expected success, got exit %d\n%s", r.ExitCode, r.describe())
	}
	return r
}

// AssertFailed asserts that mrs exited unsuccessfully.
func (r *result) AssertFailed() *result {
	r.t.Helper()
	if r.ExitCode == 0 {
		r.t.Fatalf("expected failure, got exit 0\n%s", r.describe())
	}
	return r
}

// AssertUsageError asserts the status mrs gives a wrong invocation, which a
// script uses to tell a command it typed wrong from one that ran and failed.
func (r *result) AssertUsageError() *result {
	r.t.Helper()
	if r.ExitCode != 2 {
		r.t.Fatalf("expected exit 2 for a wrong invocation, got exit %d\n%s", r.ExitCode, r.describe())
	}
	return r
}

// AssertStdout asserts that stdout contains the given substring.
func (r *result) AssertStdout(want string) *result {
	r.t.Helper()
	if !strings.Contains(r.Stdout, want) {
		r.t.Fatalf("expected stdout to contain %q\n%s", want, r.describe())
	}
	return r
}

// AssertCommandListed asserts that a help listing names the given command,
// anchored to the first field of a line. A substring would match the name
// wherever it fell: "rm" is inside the "for more information" footer cobra
// prints under every listing, so `AssertStdout("rm")` passes for a command that
// is not there at all.
func (r *result) AssertCommandListed(want string) *result {
	r.t.Helper()
	for line := range strings.SplitSeq(r.Stdout, "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == want {
			return r
		}
	}
	r.t.Fatalf("expected stdout to list the command %q\n%s", want, r.describe())
	return r
}

// AssertStdoutEquals asserts stdout exactly, after trimming a trailing newline.
func (r *result) AssertStdoutEquals(want string) *result {
	r.t.Helper()
	if got := strings.TrimSuffix(r.Stdout, "\n"); got != want {
		r.t.Fatalf("expected stdout %q, got %q\n%s", want, got, r.describe())
	}
	return r
}

// AssertStdoutExactly asserts stdout byte for byte, including its final newline.
func (r *result) AssertStdoutExactly(want string) *result {
	r.t.Helper()
	if r.Stdout != want {
		r.t.Fatalf("expected stdout %q, got %q\n%s", want, r.Stdout, r.describe())
	}
	return r
}

// AssertStderr asserts that stderr contains the given substring.
func (r *result) AssertStderr(want string) *result {
	r.t.Helper()
	if !strings.Contains(r.Stderr, want) {
		r.t.Fatalf("expected stderr to contain %q\n%s", want, r.describe())
	}
	return r
}

// AssertNoOutput asserts that the given substring appears nowhere in the
// output, which is how we check that secrets do not leak.
func (r *result) AssertNoOutput(unwanted string) *result {
	r.t.Helper()
	if strings.Contains(r.Stdout, unwanted) || strings.Contains(r.Stderr, unwanted) {
		r.t.Fatalf("expected output not to contain %q\n%s", unwanted, r.describe())
	}
	return r
}

// assertFileMode asserts a file's permission bits.
func assertFileMode(t *testing.T, p string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("failed to stat %s: %s", p, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Fatalf("expected %s to have mode %o, got %o", p, want, got)
	}
}

// assertNotExists asserts that a path is absent.
func assertNotExists(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("expected %s not to exist (stat err: %v)", p, err)
	}
}

// readFile reads a file or fails the test.
func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("failed to read %s: %s", p, err)
	}
	return string(b)
}
