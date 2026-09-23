package fs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/andornaut/mrs/internal/config"
)

func TestATemporaryFileIsWrittenReadableOnlyByItsOwner(t *testing.T) {
	// The temp dir is remembered for the process, so a previous test's must be
	// forgotten for this one's MRS_TEMP to be read.
	config.Reset()
	t.Cleanup(config.Reset)
	tmpRoot := t.TempDir()
	t.Setenv("MRS_TEMP", tmpRoot)

	content := "secret data"
	path, err := WriteTempFile([]byte(content))
	if err != nil {
		t.Fatalf("WriteTempFile() error = %v", err)
	}
	defer func() { _ = os.Remove(path) }()

	// Verify content
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Errorf("WriteTempFile() content = %v, expected %v", string(got), content)
	}

	// Verify permissions
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("WriteTempFile() permissions = %v, expected 0600", info.Mode().Perm())
	}
}

func TestAnAtomicWriteLeavesTheContentAndNoTemporaryFile(t *testing.T) {
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, "target")

	if err := WriteFileAtomic(p, []byte("first"), 0600); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first" {
		t.Errorf("content = %q, expected %q", string(got), "first")
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("permissions = %v, expected 0600", info.Mode().Perm())
	}

	// No temporary files should be left behind
	matches, err := filepath.Glob(filepath.Join(tmpDir, "*"+TempSuffix))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Errorf("leftover temp files: %v", matches)
	}
}

// An existing file's mode is kept, but only as far as the owner's bits: a
// vault left readable by everyone would otherwise stay that way through every
// save, while a stricter mode the user chose is not undone by one.
func TestAnExistingFilesModeIsKeptOnlyAsFarAsTheOwnersBits(t *testing.T) {
	tests := []struct {
		before, want os.FileMode
	}{
		{0644, 0600},
		{0666, 0600},
		{0640, 0600},
		{0604, 0600},
		{0777, 0700},
		{0600, 0600},
		{0400, 0400},
	}
	for _, tt := range tests {
		tmpDir := t.TempDir()
		p := filepath.Join(tmpDir, "target")
		if err := os.WriteFile(p, []byte("old"), tt.before); err != nil {
			t.Fatal(err)
		}
		// os.WriteFile applies the umask, so set the mode explicitly.
		if err := os.Chmod(p, tt.before); err != nil {
			t.Fatal(err)
		}

		if err := WriteFileAtomic(p, []byte("new"), 0600); err != nil {
			t.Fatalf("WriteFileAtomic() error = %v", err)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != tt.want {
			t.Errorf("mode %04o became %04o, expected %04o", tt.before, info.Mode().Perm(), tt.want)
		}
	}
}

// A write that fails once the temporary file exists must not leave it behind.
// A stale ".tmp" beside a vault holds whatever was last written to it, and only
// the write that made it knows it is no longer wanted.
func TestAFailedWriteLeavesNoTemporaryFileBehind(t *testing.T) {
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, "target")
	// A directory where the file should be, so that the temporary file is
	// created and written and only the rename onto it fails.
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}

	if err := WriteFileAtomic(p, []byte("new"), 0600); err == nil {
		t.Fatal("expected WriteFileAtomic() to fail writing onto a directory")
	}

	matches, err := filepath.Glob(filepath.Join(tmpDir, "*"+TempSuffix))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Errorf("leftover temp files: %v", matches)
	}
}

// A parent directory that cannot be synced is not a failed write. The file was
// written and renamed and is already visible; only the hardening of that rename
// against power loss was missed, so the error wraps ErrDirSync and the callers
// that know a vault was written go on rather than reporting a failed save.
func TestAnUnsyncableParentDirectoryIsReportedAsErrDirSync(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which permission bits do not restrain")
	}
	dir := filepath.Join(t.TempDir(), "write-only")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	// Writable and enterable but not readable, so the temporary file is created
	// and renamed and only opening the directory to sync it fails.
	if err := os.Chmod(dir, 0300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	p := filepath.Join(dir, "target")
	err := WriteFileAtomic(p, []byte("new"), 0600)

	if !errors.Is(err, ErrDirSync) {
		t.Fatalf("WriteFileAtomic() = %v, want an error wrapping ErrDirSync", err)
	}
	// And what stopped the sync, so that the warning a caller prints says which
	// failure it was rather than only that there was one.
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("WriteFileAtomic() = %v, want it to name the permission failure", err)
	}
	got, readErr := os.ReadFile(p)
	if readErr != nil {
		t.Fatalf("expected the file to have been written anyway: %v", readErr)
	}
	if string(got) != "new" {
		t.Errorf("content = %q, expected %q", string(got), "new")
	}
}

func TestAWriteThroughASymlinkReachesItsTargetAndKeepsTheLink(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "target")
	link := filepath.Join(tmpDir, "link")
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := WriteFileAtomic(link, []byte("new"), 0600); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v", err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink was replaced by a regular file")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("target content = %q, expected %q", string(got), "new")
	}
}

// A run that decrypted nothing created no temporary directory, and its cleanup
// must not create one either: asking for the directory in order to remove it
// would make one on every such run, and would report a directory that could not
// be created as secrets left on disk.
func TestCleanupOfARunThatDecryptedNothingCreatesNoTempDir(t *testing.T) {
	config.Reset()
	t.Cleanup(config.Reset)
	tmpRoot := t.TempDir()
	t.Setenv("MRS_TEMP", tmpRoot)

	if err := RemoveTempDir(); err != nil {
		t.Fatalf("RemoveTempDir() error: %v", err)
	}

	entries, err := os.ReadDir(tmpRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("expected the cleanup to create nothing, found %v", entries)
	}
}

// A write replaces the file rather than rewriting it in place: a reader that
// opened the old file goes on reading the old contents, and never a mixture of
// old and new or a truncated file.
func TestAnAtomicWriteReplacesTheFileRatherThanRewritingIt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault")
	if err := os.WriteFile(p, []byte("old contents"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()

	if err = WriteFileAtomic(p, []byte("new"), 0600); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v", err)
	}

	after, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Error("WriteFileAtomic() rewrote the file in place rather than replacing it")
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old contents" {
		t.Errorf("a reader of the old file read %q, want %q", got, "old contents")
	}
}

// The sweep removes only the names WriteFileAtomic's temporary files are given.
// Beside a symlinked vault's target it runs in a directory of the user's, where
// a file that merely shares the prefix and the suffix is theirs.
func TestRemoveTempFilesRemovesOnlyAtomicWriteLeftovers(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "report.txt")
	f, err := os.CreateTemp(dir, "report.txt.*"+TempSuffix)
	if err != nil {
		t.Fatal(err)
	}
	leftover := f.Name()
	_ = f.Close()
	kept := []string{"report.txt.draft.tmp", "report.txt..tmp", "report.txt.12a.tmp", "other.txt.123.tmp"}
	for _, name := range kept {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}

	if err := RemoveTempFiles(p); err != nil {
		t.Fatalf("RemoveTempFiles() error = %v", err)
	}

	if _, err := os.Stat(leftover); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected %s to be removed, stat err = %v", leftover, err)
	}
	for _, name := range kept {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to be kept, stat err = %v", name, err)
		}
	}
}
