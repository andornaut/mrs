package vault

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/andornaut/mrs/internal/config"
)

// testSalt stands in for the salt crypto.Salt() generates: 32 characters of
// base64url, which is the shape a vault filename must carry.
const testSalt = "12345678901234567890123456789012"

// newVaultDir points mrs at an empty vault directory and returns it.
func newVaultDir(t *testing.T) string {
	t.Helper()
	config.Reset()
	t.Setenv("MRS_HOME", t.TempDir())
	dir, err := config.GetVaultDir()
	if err != nil {
		t.Fatalf("failed to get vault dir: %v", err)
	}
	return dir
}

// writeFile writes a file into the vault directory. Nothing here decrypts, so
// a vault's ciphertext is stood in for by arbitrary bytes.
func writeFile(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("contents"), 0600); err != nil {
		t.Fatalf("failed to write %s: %v", name, err)
	}
}

// entriesIn returns the names of the files in a directory.
func entriesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestFindVaultsIgnoresEverythingThatIsNotAVault(t *testing.T) {
	dir := newVaultDir(t)
	writeFile(t, dir, "test."+testSalt)
	// A vault's own companion files, and files that other programs leave in a
	// data directory. None of them names a vault.
	for _, name := range []string{
		"test.lock",
		"test." + testSalt + ".bak",
		"test." + testSalt + ".1234.tmp",
		".DS_Store",
		".test.swp",
		"notes.txt.orig",
		"README.md",
	} {
		writeFile(t, dir, name)
	}

	vaults, err := All()
	if err != nil {
		t.Fatalf("All() failed: %v", err)
	}
	if len(vaults) != 1 || vaults[0].Name() != "test" {
		t.Errorf("expected only the vault named test, got %v", names(vaults))
	}
}

func TestDeleteRemovesTheVaultAndItsCompanionFiles(t *testing.T) {
	dir := newVaultDir(t)
	for _, name := range []string{
		"test." + testSalt,
		"test." + testSalt + ".bak",
		"test." + testSalt + ".1234.tmp",
		"test.lock",
	} {
		writeFile(t, dir, name)
	}

	v, err := Exact("test")
	if err != nil {
		t.Fatalf("Exact() failed: %v", err)
	}
	if err = Delete(v); err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}

	// The lock file is left in place, as by every other command, and is
	// harmless because it is re-lockable once no process holds it.
	if got := entriesIn(t, dir); len(got) != 1 || got[0] != "test.lock" {
		t.Errorf("expected only the lock file to remain after delete, got %v", got)
	}
}

func TestDeleteReportsBackupRemovalFailure(t *testing.T) {
	dir := newVaultDir(t)
	writeFile(t, dir, "test."+testSalt)
	// A non-empty directory at the backup's path makes os.Remove fail with
	// something other than "not exist".
	bakDir := filepath.Join(dir, "test."+testSalt+".bak")
	if err := os.Mkdir(bakDir, 0700); err != nil {
		t.Fatalf("failed to create backup dir: %v", err)
	}
	writeFile(t, bakDir, "child")

	v, err := Exact("test")
	if err != nil {
		t.Fatalf("Exact() failed: %v", err)
	}
	// A leftover backup still holds the secrets, so failing to remove it is an
	// error rather than a warning.
	if err = Delete(v); err == nil {
		t.Fatal("expected Delete() to return an error when the backup cannot be removed")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "test."+testSalt)); !os.IsNotExist(statErr) {
		t.Errorf("expected the vault itself to be deleted, stat err = %v", statErr)
	}
}

func TestRenameReportsBackupMoveFailure(t *testing.T) {
	dir := newVaultDir(t)
	writeFile(t, dir, "src."+testSalt)
	writeFile(t, dir, "src."+testSalt+".bak")
	// Renaming a file onto a directory fails with EISDIR.
	targetPath := filepath.Join(dir, "dst."+testSalt)
	if err := os.Mkdir(targetPath+".bak", 0700); err != nil {
		t.Fatalf("failed to create target backup dir: %v", err)
	}

	src, err := Exact("src")
	if err != nil {
		t.Fatalf("Exact() failed: %v", err)
	}
	if err = Rename(src, "dst", false); err == nil {
		t.Fatal("expected Rename() to return an error when the backup cannot be moved")
	}
	// The vault itself must still have been renamed, so that the error names
	// what actually happened.
	if _, statErr := os.Stat(targetPath); statErr != nil {
		t.Errorf("expected renamed vault at %q, stat err = %v", targetPath, statErr)
	}
}

// A rename claims a name, so it takes that name's lock before asking whether
// the name is free. Without it, a create or another rename could claim the same
// name between the answer and the rename, leaving two vault files carrying it.
func TestRenameIsRefusedWhileTheTargetNameIsLocked(t *testing.T) {
	dir := newVaultDir(t)
	writeFile(t, dir, "src."+testSalt)

	held, err := Vault(filepath.Join(dir, "dst")).ExclusiveLock()
	if err != nil {
		t.Fatalf("failed to hold the target name's lock: %v", err)
	}
	defer held()

	src, err := Exact("src")
	if err != nil {
		t.Fatalf("Exact() failed: %v", err)
	}
	if err = Rename(src, "dst", false); err == nil {
		t.Fatal("expected Rename() to be refused while the target name is locked")
	}
	// The source must be left alone, so that a refused rename changes nothing.
	if _, statErr := os.Stat(filepath.Join(dir, "src."+testSalt)); statErr != nil {
		t.Errorf("expected the source vault to be untouched, stat err = %v", statErr)
	}
}

// A name lock is never broken, because breaking one deletes the lock file and
// two processes that each broke it would go on to lock two different files.
// Nothing that claims a name may be forced past another claim on it.
func TestCreateAndRenameDoNotBreakANameLock(t *testing.T) {
	dir := newVaultDir(t)
	writeFile(t, dir, "src."+testSalt)

	held, err := Vault(filepath.Join(dir, "dst")).ExclusiveLock()
	if err != nil {
		t.Fatalf("failed to hold the target name's lock: %v", err)
	}
	defer held()

	src, err := Exact("src")
	if err != nil {
		t.Fatalf("Exact() failed: %v", err)
	}
	if err = Rename(src, "dst", false); err == nil {
		t.Error("expected Rename() to be refused rather than break the target name's lock")
	}
	if _, err = Create("dst", []byte("a password"), nil, false); err == nil {
		t.Error("expected Create() to be refused rather than break the name's lock")
	}
	// Neither may have left a file under the locked name.
	for _, name := range entriesIn(t, dir) {
		if name == "dst."+testSalt || (len(name) > 4 && name[:4] == "dst." && name != "dst.lock") {
			t.Errorf("expected no vault file under the locked name, found %q", name)
		}
	}
}

// Vaults are listed sorted by name ignoring case, as secrets are sorted by key.
// Filename order would put every uppercase name ahead of every lowercase one,
// and "_under" between "Banana" and "mango".
func TestAllSortsNamesIgnoringCase(t *testing.T) {
	dir := newVaultDir(t)
	for _, name := range []string{"zebra", "Apple", "mango", "_under", "Banana", "App"} {
		writeFile(t, dir, name+"."+testSalt)
	}

	vs, err := All()
	if err != nil {
		t.Fatalf("All() failed: %v", err)
	}
	want := []string{"_under", "App", "Apple", "Banana", "mango", "zebra"}
	if got := names(vs); !slices.Equal(got, want) {
		t.Errorf("expected %v, got %v", want, got)
	}
}

// Names that differ only in case fall back to byte order, so that a listing is
// the same on every run.
func TestAllOrdersNamesThatDifferOnlyInCase(t *testing.T) {
	dir := newVaultDir(t)
	for _, name := range []string{"app", "APP", "App"} {
		writeFile(t, dir, name+"."+testSalt)
	}

	vs, err := All()
	if err != nil {
		t.Fatalf("All() failed: %v", err)
	}
	want := []string{"APP", "App", "app"}
	if got := names(vs); !slices.Equal(got, want) {
		t.Errorf("expected %v, got %v", want, got)
	}
}

// A vault whose file is a symlink to a target that is not there - a drive that
// is not mounted, a store moved elsewhere - is a vault like any other. It is
// listed and it holds its name; only the commands that have to read it fail,
// as they do for a vault at a key derivation mrs no longer supports.
func TestADanglingVaultSymlinkIsAVaultLikeAnyOther(t *testing.T) {
	dir := newVaultDir(t)
	writeFile(t, dir, "here."+testSalt)
	if err := os.Symlink(filepath.Join(dir, "not-mounted"), filepath.Join(dir, "away."+testSalt)); err != nil {
		t.Fatalf("failed to create the dangling symlink: %v", err)
	}

	vs, err := All()
	if err != nil {
		t.Fatalf("All() failed: %v", err)
	}
	if got := names(vs); len(got) != 2 || got[0] != "away" || got[1] != "here" {
		t.Errorf("expected both vaults to be listed, got %v", got)
	}
	// Naming it resolves, so that delete and rename can reach it.
	if _, exactErr := Exact("away"); exactErr != nil {
		t.Errorf("expected Exact() to find the dangling vault, got %v", exactErr)
	}

	taken, err := Exists("away")
	if err != nil {
		t.Fatalf("Exists() failed: %v", err)
	}
	if !taken {
		t.Error("expected the dangling vault to hold its name")
	}
	if _, err := Create("away", []byte("a password"), nil, false); err == nil {
		t.Error("expected Create() to refuse a name a dangling vault holds")
	}
	if err := Rename(Vault(filepath.Join(dir, "here."+testSalt)), "away", false); err == nil {
		t.Error("expected Rename() to refuse a name a dangling vault holds")
	}
}

// Exists asks of the filename, so the files that live alongside a vault never
// make its name look taken. A name whose vault was deleted has to be free
// again, and delete leaves the lock file behind.
func TestExistsIgnoresTheFilesBesideAVault(t *testing.T) {
	dir := newVaultDir(t)
	for _, name := range []string{
		"gone.lock",
		"gone." + testSalt + ".bak",
		"gone." + testSalt + ".1234.tmp",
	} {
		writeFile(t, dir, name)
	}

	taken, err := Exists("gone")
	if err != nil {
		t.Fatalf("Exists() failed: %v", err)
	}
	if taken {
		t.Error("expected a name with only a vault's companion files left behind to be free")
	}
}
