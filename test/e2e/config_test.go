package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Capability 7: where mrs puts things. Every other test pins MRS_HOME and
// MRS_TEMP at a lab directory, so the environment variables mrs falls back to
// when they are absent are exercised only here.

// editorStat is what the fake editor saw while the plaintext file was open.
// It has to be captured from inside the session, because mrs removes the file
// and its directory before it exits.
type editorStat struct {
	FileMode string
	DirMode  string
	Path     string
}

// editSession runs an edit and reports where mrs put the plaintext file it
// handed the editor, which is how a test sees which temporary directory mrs
// chose and how exposed the file was while it was there.
func (l *lab) editSession(name, pwFile string) editorStat {
	l.t.Helper()
	statFile := filepath.Join(filepath.Dir(l.Home), "editor-stat")
	l.Setenv("FAKE_EDITOR_STAT", statFile)
	l.Run("edit", "-v", name, "-p", pwFile).AssertOK()

	raw := strings.TrimSpace(readFile(l.t, statFile))
	var s editorStat
	for _, field := range strings.SplitN(raw, " ", 3) {
		k, v, found := strings.Cut(field, "=")
		if !found {
			l.t.Fatalf("expected the editor to report file, dir and path, got %q", raw)
		}
		switch k {
		case "file":
			s.FileMode = v
		case "dir":
			s.DirMode = v
		case "path":
			s.Path = v
		}
	}
	if s.Path == "" || s.DirMode == "" {
		l.t.Fatalf("expected the editor to report file, dir and path, got %q", raw)
	}
	return s
}

// vaultFilesIn returns the vault files in a directory, ignoring the lock files
// that every command leaves behind.
func vaultFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read %s: %s", dir, err)
	}
	var names []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".lock") {
			names = append(names, e.Name())
		}
	}
	return names
}

// assertDirMode asserts a directory's permission bits.
func assertDirMode(t *testing.T, p string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("failed to stat %s: %s", p, err)
	}
	if !fi.IsDir() {
		t.Fatalf("expected %s to be a directory", p)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Fatalf("expected %s to have mode %o, got %o", p, want, got)
	}
}

func TestVaultsAreStoredUnderMrsHome(t *testing.T) {
	l := newLab(t)
	l.createVault("personal", "a password")

	// The directory is created on demand, and holds secrets, so it is private.
	assertDirMode(t, l.VaultDir(), 0700)
	if got := l.VaultPath("personal"); filepath.Dir(got) != l.VaultDir() {
		t.Fatalf("expected the vault under %s, got %s", l.VaultDir(), got)
	}
}

func TestMrsHomeIsCreatedOnDemand(t *testing.T) {
	l := newLab(t)
	// A path several levels below anything that exists, as a fresh machine or
	// a new value of MRS_HOME would give.
	home := filepath.Join(l.UserHome, "a", "b", "c", "mrs")
	l.Setenv("MRS_HOME", home)

	l.Run("vault", "create", "-v", "personal", "-p", l.PasswordFile("pw", "a password")).AssertOK()

	assertDirMode(t, filepath.Join(home, "vaults"), 0700)
}

func TestXdgDataHomeIsUsedWhenMrsHomeIsUnset(t *testing.T) {
	l := newLab(t)
	xdg := filepath.Join(l.UserHome, "xdg-data")
	l.Unsetenv("MRS_HOME")
	l.Setenv("XDG_DATA_HOME", xdg)

	l.Run("vault", "create", "-v", "personal", "-p", l.PasswordFile("pw", "a password")).AssertOK()

	vaults := filepath.Join(xdg, "mrs", "vaults")
	assertDirMode(t, vaults, 0700)
	if got := vaultFilesIn(t, vaults); len(got) != 1 {
		t.Fatalf("expected one vault under %s, got %v", vaults, got)
	}
}

func TestMrsHomeWinsOverXdgDataHome(t *testing.T) {
	l := newLab(t)
	xdg := filepath.Join(l.UserHome, "xdg-data")
	l.Setenv("XDG_DATA_HOME", xdg)

	l.createVault("personal", "a password")

	// MRS_HOME is the more specific setting, so it is the one that applies.
	l.Run("vault", "list").AssertOK().AssertStdoutEquals("personal")
	assertNotExists(t, filepath.Join(xdg, "mrs"))
}

func TestTheHomeDirectoryIsUsedWhenNothingElseIsSet(t *testing.T) {
	l := newLab(t)
	l.Unsetenv("MRS_HOME")
	l.Unsetenv("XDG_DATA_HOME")

	l.Run("vault", "create", "-v", "personal", "-p", l.PasswordFile("pw", "a password")).AssertOK()

	// The documented default, below $HOME rather than anywhere absolute.
	assertDirMode(t, filepath.Join(l.UserHome, ".local", "share", "mrs", "vaults"), 0700)
}

func TestAnUnusableHomeIsReportedByEveryCommand(t *testing.T) {
	l := newLab(t)
	pwFile := l.PasswordFile("pw", "a password")
	notADir := l.WriteFile("not-a-dir", "")
	l.Setenv("MRS_HOME", notADir)

	// Whichever command the user reaches for, the answer must name the
	// problem rather than report an empty or missing vault.
	for _, args := range [][]string{
		{"vault", "list"},
		{"vault", "default"},
		{"vault", "create", "-v", "personal", "-p", pwFile},
		{"vault", "export", "-v", "personal", "-p", pwFile},
		{"search", "-v", "personal", "-p", pwFile, "anything"},
	} {
		l.Run(args...).AssertFailed().AssertStderr("not a directory")
	}
}

func TestPlaintextIsEditedUnderMrsTemp(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")

	s := l.editSession("personal", pwFile)

	if !strings.HasPrefix(s.Path, l.Temp) {
		t.Fatalf("expected the decrypted file under MRS_TEMP (%s), got %q", l.Temp, s.Path)
	}
	// mrs makes a fresh private directory per run rather than editing directly
	// in the shared one.
	if s.DirMode != "0700" {
		t.Fatalf("expected the decrypted file's directory to be private, got %q", s.DirMode)
	}
	if filepath.Dir(s.Path) == l.Temp {
		t.Fatalf("expected a directory of its own below %s, got %q", l.Temp, s.Path)
	}
}

func TestXdgRuntimeDirIsUsedWhenMrsTempIsUnset(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")
	runtimeDir := filepath.Join(l.UserHome, "xdg-runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatalf("failed to create %s: %s", runtimeDir, err)
	}
	l.Unsetenv("MRS_TEMP")
	l.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	s := l.editSession("personal", pwFile)

	// XDG_RUNTIME_DIR is preferred over the system temporary directory,
	// because it is already private to the user and cleared on logout.
	if !strings.HasPrefix(s.Path, filepath.Join(runtimeDir, "mrs")) {
		t.Fatalf("expected the decrypted file under %s, got %q", runtimeDir, s.Path)
	}
}

func TestTheSystemTemporaryDirectoryIsTheLastResort(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")
	tmp := filepath.Join(l.UserHome, "system-tmp")
	if err := os.MkdirAll(tmp, 0700); err != nil {
		t.Fatalf("failed to create %s: %s", tmp, err)
	}
	l.Unsetenv("MRS_TEMP")
	l.Unsetenv("XDG_RUNTIME_DIR")
	l.Setenv("TMPDIR", tmp)

	s := l.editSession("personal", pwFile)

	if !strings.HasPrefix(s.Path, filepath.Join(tmp, "mrs")) {
		t.Fatalf("expected the decrypted file under %s, got %q", tmp, s.Path)
	}
}

func TestMrsTempWinsOverXdgRuntimeDir(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")
	runtimeDir := filepath.Join(l.UserHome, "xdg-runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatalf("failed to create %s: %s", runtimeDir, err)
	}
	l.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	s := l.editSession("personal", pwFile)

	if !strings.HasPrefix(s.Path, l.Temp) {
		t.Fatalf("expected MRS_TEMP (%s) to win, got %q", l.Temp, s.Path)
	}
	assertNotExists(t, filepath.Join(runtimeDir, "mrs"))
}

func TestAnUnusableTempIsReported(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\nthe-secret-value\n")
	notADir := l.WriteFile("not-a-dir", "")
	l.Setenv("MRS_TEMP", notADir)

	// An edit cannot write the plaintext anywhere, so it must fail rather than
	// fall back to somewhere less private.
	l.Run("edit", "-v", "personal", "-p", pwFile).
		AssertFailed().
		AssertStderr("not a directory").
		AssertNoOutput("the-secret-value")

	// A command that never needs a temporary file is unaffected.
	l.Run("vault", "export", "-v", "personal", "-p", pwFile).
		AssertOK().
		AssertStdout("the-secret-value")
}

func TestTheDefaultVaultNameSelectsAmongSeveral(t *testing.T) {
	l := newLab(t)
	workPw := l.seedVault("work", "a password", "work key\nwork-value\n")
	l.seedVault("home", "a password", "home key\nhome-value\n")
	l.Setenv("MRS_DEFAULT_VAULT_NAME", "work")

	// With no -v, the configured vault is the one that is used, not the first
	// in the directory, which would be "home".
	l.Run("vault", "default").AssertOK().AssertStdoutEquals("work")
	l.Run("search", "-p", workPw, "work").AssertOK().AssertStdout("work-value")

	l.editorAppends("added key\nadded-value\n")
	l.Run("add", "-p", workPw).AssertOK().AssertStderr("added to vault work")
	if got := l.export("home", l.PasswordFile("home2.pw", "a password")); strings.Contains(got, "added-value") {
		t.Fatal("expected the configured vault to be used, not the first in the directory")
	}
}

func TestTheVaultSubcommandsRequireANamedVault(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "work key\nwork-value\n")
	l.Setenv("MRS_DEFAULT_VAULT_NAME", "work")

	// A vault that is about to be changed is named, whether by --vault or by
	// answering the prompt: the configured default is a convenience for the
	// commands that read, and is not enough to re-key or delete by.
	for _, args := range [][]string{
		{"vault", "change-password", "-p", pwFile},
		{"vault", "delete"},
	} {
		l.Run(args...).AssertFailed().AssertStderr("--vault")
	}

	// Answering the prompt works, as does naming it on the command line.
	l.RunStdin("work\n", "vault", "change-password", "-p", pwFile, "-n", pwFile).
		AssertOK().
		AssertStderr("Changed password of vault work")

	// export only reads, so it resolves the default the way search does.
	l.Run("vault", "export", "-p", pwFile).AssertOK().AssertStdout("work-value")
	l.Run("vault", "export", "-v", "work", "-p", pwFile).AssertOK().AssertStdout("work-value")
}

func TestTheOnlyVaultIsUsedWhenNoneIsNamed(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("solo", "a password", "a key\nsolo-value\n")

	// With one vault and nothing configured, there is nothing to disambiguate,
	// so add, edit and search use it rather than asking which.
	l.Run("search", "-p", pwFile, "a key").AssertOK().AssertStdout("solo-value")
	l.Run("edit", "-p", pwFile).AssertOK().AssertStderr("vault solo")
}

func TestAnExplicitVaultOverridesTheDefaultVaultName(t *testing.T) {
	l := newLab(t)
	l.seedVault("work", "a password", "work key\nwork-value\n")
	homePw := l.seedVault("home", "a password", "home key\nhome-value\n")
	l.Setenv("MRS_DEFAULT_VAULT_NAME", "work")

	l.Run("vault", "export", "-v", "home", "-p", homePw).
		AssertOK().
		AssertStdoutExactly("home key\nhome-value\n")
}

func TestTheDefaultVaultNameMustNameAVaultExactly(t *testing.T) {
	l := newLab(t)
	l.seedVault("personal", "a password", "a key\na value\n")

	// A prefix is accepted on the command line, where it is typed and read in
	// the same moment. A name written into a shell profile is read on every run
	// and looked at almost never, so it has to name a vault exactly.
	for _, name := range []string{"pers", "personal2", "absent"} {
		l.Setenv("MRS_DEFAULT_VAULT_NAME", name)
		l.Run("vault", "default").
			AssertFailed().
			AssertStderr("not found").
			AssertStderr("MRS_DEFAULT_VAULT_NAME must name a vault exactly")
	}

	l.Setenv("MRS_DEFAULT_VAULT_NAME", "personal")
	l.Run("vault", "default").AssertOK().AssertStdoutEquals("personal")
}

func TestEachRunGetsItsOwnTemporaryDirectory(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("personal", "a password", "a key\na value\n")

	first := l.editSession("personal", pwFile)
	second := l.editSession("personal", pwFile)

	// Two runs must not share a path, so that one cannot read or clobber the
	// other's plaintext.
	if filepath.Dir(first.Path) == filepath.Dir(second.Path) {
		t.Fatalf("expected each run its own directory, got %q twice", filepath.Dir(first.Path))
	}
	// And neither survives the run that made it.
	assertNotExists(t, first.Path)
	assertNotExists(t, second.Path)
	assertNoPlaintextUnder(t, l.Temp, "a value")
}

func TestAPromptNeverReachesStdout(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\nthe-secret-value\n")

	// `mrs vault create > log` asks which vault to create. The question has to
	// reach the user's terminal, not the file they are capturing.
	r := l.RunStdin("second\n", "vault", "create", "-p", pwFile).AssertOK()
	r.AssertStderr("Vault name: ")
	r.AssertStdoutExactly("")

	// And a vault's secrets reach stdout with nothing else mixed in.
	l.Run("vault", "export", "-v", "work", "-p", pwFile).
		AssertOK().
		AssertStdoutExactly("a key\nthe-secret-value\n")

	// A prompt answered from a pipe is not echoed, so mrs supplies the newline
	// that pressing Enter would have written. Without it, whatever it prints
	// next continues the prompt's line, as in "Vault name: Error: ...".
	r = l.Run("vault", "create", "-p", pwFile).AssertFailed()
	if strings.Contains(r.Stderr, "Vault name: Error") {
		t.Errorf("expected the error on its own line, got %q", r.Stderr)
	}
	r.AssertStderr("Use --vault to name one")

	// And the question before a destructive change, which without a terminal
	// is reported rather than asked.
	r = l.Run("vault", "delete", "-v", "work").AssertFailed()
	r.AssertStderr("Delete vault work?")
	if strings.Contains(r.Stdout, "Delete vault") {
		t.Fatalf("expected the confirmation off stdout, got %q", r.Stdout)
	}
}

// TestNothingButDataIsEverWrittenToStdout is the general form of the rule the
// tests above check case by case: whatever goes wrong, stdout stays empty, so
// a caller redirecting it captures secrets or nothing at all.
func TestNothingButDataIsEverWrittenToStdout(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\nthe-secret-value\n")
	wrong := l.PasswordFile("wrong.pw", "not the password")
	absent := filepath.Join(l.UserHome, "absent")

	failures := map[string][]string{
		"unknown command":       {"bogus"},
		"unknown subcommand":    {"vault", "bogus"},
		"unknown flag":          {"vault", "list", "--bogus"},
		"missing vault":         {"vault", "export", "-v", "nope", "-p", pwFile},
		"wrong password":        {"vault", "export", "-v", "work", "-p", wrong},
		"missing password file": {"vault", "export", "-v", "work", "-p", absent},
		"no answer to confirm":  {"vault", "delete", "-v", "work"},
		"no password to read":   {"vault", "export", "-v", "work"},
		"search without a term": {"search", "-v", "work", "-p", pwFile},
		"invalid pattern":       {"search", "-v", "work", "-p", pwFile, "["},
		"search found nothing":  {"search", "-v", "work", "-p", pwFile, "zzz"},
		"duplicate vault":       {"vault", "create", "-v", "work", "-p", pwFile},
		"invalid vault name":    {"vault", "create", "-v", "bad name", "-p", pwFile},
		"weak password":         {"vault", "create", "-v", "new", "-p", l.PasswordFile("short.pw", "short")},
		"rename missing source": {"vault", "rename", "nope", "other"},
		"rename too few args":   {"vault", "rename", "onlyone"},
		"delete missing vault":  {"vault", "delete", "-v", "nope"},
		"prefix cannot delete":  {"vault", "delete", "-v", "wor"},
		"prefix cannot re-key":  {"vault", "change-password", "-v", "wor", "-p", pwFile},
	}
	for desc, args := range failures {
		t.Run(desc, func(t *testing.T) {
			r := l.Run(args...).AssertFailed()
			if r.Stdout != "" {
				t.Errorf("expected nothing on stdout, got %q", r.Stdout)
			}
			if r.Stderr == "" {
				t.Errorf("expected the failure to be explained on stderr, got nothing")
			}
			if strings.Contains(r.Stdout, "the-secret-value") {
				t.Errorf("expected no secret in the output, got %q", r.Stdout)
			}
		})
	}
}

// 2 is kept for a wrong invocation and 3 for a search that matched nothing, so
// that a script can tell a command it typed wrong, one that ran and failed, and
// one that ran and found nothing apart.
func TestExitCodesDistinguishUsageFromFailureFromNoMatch(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")

	for _, c := range []struct {
		desc string
		args []string
		want int
	}{
		{"a search that matched", []string{"search", "-v", "work", "-p", pwFile, "a key"}, 0},
		{"a command that worked", []string{"vault", "list"}, 0},
		{"a vault that is not there", []string{"search", "-v", "nope", "-p", pwFile, "a key"}, 1},
		{"a password that is wrong", []string{"vault", "export", "-v", "work", "-p", l.PasswordFile("wrong.pw", "not the password")}, 1},
		{"a confirmation nobody can answer", []string{"vault", "delete", "-v", "work"}, 1},
		{"a flag that is not there", []string{"vault", "list", "--bogus"}, 2},
		{"a command that is not there", []string{"bogus"}, 2},
		{"a subcommand that is not there", []string{"vault", "bogus"}, 2},
		{"an argument a command does not take", []string{"vault", "list", "extra"}, 2},
		{"a search with nothing to search for", []string{"search", "-v", "work", "-p", pwFile}, 2},
		{"a search that matched nothing", []string{"search", "-v", "work", "-p", pwFile, "zzz"}, 3},
	} {
		t.Run(c.desc, func(t *testing.T) {
			if r := l.Run(c.args...); r.ExitCode != c.want {
				t.Errorf("expected exit %d, got %d\n%s", c.want, r.ExitCode, r.describe())
			}
		})
	}
}

// The rule stated on the success path: stdout carries the vault names, paths
// and secrets a caller consumes, and every report of what happened goes to
// stderr, so that redirecting stdout captures data alone.
func TestOnlyDataIsWrittenToStdoutWhenACommandSucceeds(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")
	l.editorAppends("added key\nadded value\n")

	for _, c := range []struct {
		desc string
		args []string
		want string
	}{
		{"create", []string{"vault", "create", "-v", "second", "-p", pwFile}, ""},
		{"add", []string{"add", "-v", "second", "-p", pwFile}, ""},
		{"edit", []string{"edit", "-v", "second", "-p", pwFile}, ""},
		{"rename", []string{"vault", "rename", "second", "third"}, ""},
		{"change-password", []string{"vault", "change-password", "-v", "third", "-p", pwFile, "-n", pwFile}, ""},
		{"delete", []string{"vault", "delete", "-v", "third", "--yes"}, ""},
		{"list", []string{"vault", "list"}, "work\n"},
		{"get-default", []string{"vault", "default"}, "work\n"},
		{"export", []string{"vault", "export", "-v", "work", "-p", pwFile}, "a key\na value\n"},
	} {
		t.Run(c.desc, func(t *testing.T) {
			r := l.Run(c.args...).AssertOK()
			if r.Stdout != c.want {
				t.Errorf("expected stdout %q, got %q\n%s", c.want, r.Stdout, r.describe())
			}
			if c.want == "" && r.Stderr == "" {
				t.Errorf("expected the outcome to be reported on stderr, got nothing")
			}
		})
	}
}

// Which of several vaults a secret belongs in is not a guess worth making on
// the user's behalf, so the commands that resolve a default ask to be told.
func TestSeveralVaultsWithNoDefaultAreNotGuessedBetween(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "a key\na value\n")
	l.seedVault("home", "a password", "a key\na value\n")

	for _, args := range [][]string{
		{"add", "-p", pwFile},
		{"edit", "-p", pwFile},
		{"search", "-p", pwFile, "a key"},
		{"vault", "export", "-p", pwFile},
		{"vault", "default"},
	} {
		l.Run(args...).
			AssertFailed().
			AssertStderr("several vaults exist").
			AssertStderr("MRS_DEFAULT_VAULT_NAME")
	}

	// Naming one, or configuring one, answers it.
	l.Run("vault", "export", "-v", "work", "-p", pwFile).AssertOK().AssertStdout("a value")
	l.Setenv("MRS_DEFAULT_VAULT_NAME", "work")
	l.Run("vault", "export", "-p", pwFile).AssertOK().AssertStdout("a value")
}
