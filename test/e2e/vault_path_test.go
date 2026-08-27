package e2e

import (
	"os"
	"path/filepath"
	"testing"
)

// Capability 12: working on a vault that is not in the vault directory, named
// by path. A vault on removable media or in a directory that is synced
// elsewhere is read and written where it is.

// outside moves a vault out of the vault directory and returns its new path,
// under newName. The salt travels with the file, because the key is derived
// from it, so a vault carries everything it needs to be opened wherever it is
// put.
func outside(l *lab, name, newName string) string {
	l.t.Helper()
	dir := filepath.Join(filepath.Dir(l.Home), "elsewhere")
	if err := os.MkdirAll(dir, 0700); err != nil {
		l.t.Fatalf("failed to create %s: %s", dir, err)
	}
	src := l.VaultPath(name)
	p := filepath.Join(dir, newName+"."+filepath.Ext(src)[1:])
	if err := os.Rename(src, p); err != nil {
		l.t.Fatalf("failed to move %s: %s", src, err)
	}
	return p
}

func TestSearchAndExportReadAVaultNamedByPath(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)
	p := outside(l, "work", "work")

	l.Run("search", "--path", p, "-p", pwFile, "github").
		AssertOK().
		AssertStdoutExactly("github\nuser: alice\ntoken: abc123\n").
		// Reported by path, because a vault named by one may share its name
		// with a vault in the vault directory.
		AssertStderr("1 secret matched \"github\" in vault " + p)

	l.Run("export", "--path", p, "-p", pwFile).AssertOK().AssertStdout("token: abc123")
}

func TestEditWritesAVaultNamedByPathWhereItIs(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", "github\ntoken: abc123\n")
	p := outside(l, "work", "work")
	l.editorAppends("\naws\nkey: xyz\n")

	l.Run("edit", "--path", p, "-p", pwFile).AssertOK().AssertStderr("Saved changes to vault " + p)

	l.Run("export", "--path", p, "-p", pwFile).AssertOK().AssertStdout("key: xyz")
	// The lock and the backup are the vault's siblings, so they are written in
	// the directory the vault is in rather than in the vault directory.
	if _, err := os.Stat(p + ".bak"); err != nil {
		t.Errorf("expected a backup beside the vault, stat err = %s", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(p), "work.lock")); err != nil {
		t.Errorf("expected a lock file beside the vault, stat err = %s", err)
	}
	// The vault directory holds only what the vault it no longer has left
	// behind: its lock file.
	if got := l.Vaults(); len(got) != 1 || got[0] != "work.lock" {
		t.Errorf("expected the vault directory to be left alone, got %v", got)
	}
}

// A path names one vault outright, so nothing is looked up: a vault of the same
// name in the vault directory is neither read nor written.
func TestAVaultNamedByPathIsNotLookedForInTheVaultDirectory(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("elsewhere", "a password", "elsewhere\nvalue: outside\n")
	// Renamed to the name the vault directory also has, which is the case that
	// tells a lookup apart from a path.
	p := outside(l, "elsewhere", "work")
	l.seedVault("work", "a password", "work\nvalue: inside\n")

	l.Run("export", "--path", p, "-p", pwFile).AssertOK().AssertStdoutExactly("elsewhere\nvalue: outside\n")
	l.Run("export", "-v", "work", "-p", pwFile).AssertOK().AssertStdoutExactly("work\nvalue: inside\n")
	// It is not listed either: `vault ls` reports the vault directory.
	l.Run("vault", "ls").AssertOK().AssertStdoutEquals("work")
}

func TestNamingAVaultByNameAndByPathIsAWrongInvocation(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)
	p := outside(l, "work", "work")

	for _, args := range [][]string{
		{"add", "--path", p, "-v", "work"},
		{"edit", "--path", p, "-v", "work"},
		{"export", "--path", p, "-v", "work"},
		{"search", "--path", p, "-v", "work", "github"},
	} {
		l.Run(append(args, "-p", pwFile)...).
			AssertUsageError().
			AssertStderr("--vault and --path both name a vault; use one").
			// A wrong invocation prints the usage that would have been right.
			AssertStderr("Usage:")
	}
}

// A vault's key is derived from the salt in its filename, so a path that does
// not carry one names no vault. It is answered before the file is looked for,
// so that the reason given is the one the user can act on.
func TestAPathThatDoesNotNameAVaultFileIsRefused(t *testing.T) {
	l := newLab(t)
	pwFile := l.seedVault("work", "a password", searchVault)
	p := outside(l, "work", "work")
	plain := l.WriteFile("notes.txt", "not a vault")

	for _, path := range []string{plain, filepath.Join(filepath.Dir(p), "work")} {
		l.Run("export", "--path", path, "-p", pwFile).
			AssertFailed().
			AssertStderr("does not name a vault").
			AssertStderr("<name>.<salt>")
	}
	l.Run("export", "--path", filepath.Join(filepath.Dir(p), "gone."+filepath.Ext(p)[1:]), "-p", pwFile).
		AssertFailed().
		AssertStderr("not found")
}
