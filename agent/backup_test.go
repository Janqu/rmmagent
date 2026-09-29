package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupCryptoRoundTripAndBlobID(t *testing.T) {
	master := bytes.Repeat([]byte{7}, 32)
	encKey, idKey := backupSubkeys(master, "repo")
	chunk := []byte("secret backup chunk")
	id1 := backupBlobID(idKey, chunk)
	id2 := backupBlobID(idKey, chunk)
	if id1 != id2 || len(id1) != 64 {
		t.Fatalf("unstable blob id: %q %q", id1, id2)
	}
	aad := []byte("repo:" + id1)
	sealed, err := backupSeal(encKey, aad, chunk)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := backupOpenForTest(encKey, aad, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, chunk) {
		t.Fatal("round trip changed chunk")
	}
	if _, err := backupOpenForTest(encKey, []byte("wrong"), sealed); err == nil {
		t.Fatal("wrong aad decrypted")
	}
}

func TestBackupExcluded(t *testing.T) {
	if !backupExcluded("/srv/data/cache.tmp", []string{"*.tmp"}) {
		t.Fatal("glob exclude missed")
	}
	if !backupExcluded("/srv/data/cache/file.txt", []string{"data/cache"}) {
		t.Fatal("path exclude missed")
	}
	if backupExcluded("/srv/data/file.txt", []string{"*.tmp"}) {
		t.Fatal("file excluded unexpectedly")
	}
}

func TestBackupRestorePath(t *testing.T) {
	root := filepath.Join("tmp", "restore")
	got, err := backupRestorePath(root, "/srv/data/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(root, "srv", "data", "file.txt") {
		t.Fatal(got)
	}
	if _, err := backupRestorePath(root, "../escape"); err == nil {
		t.Fatal("escape path accepted")
	}
}

func TestBackupAddSource(t *testing.T) {
	dir := t.TempDir()
	var sources []BackupSource
	backupAddSource(&sources, filepath.Join(dir, "missing"), "missing", "folder")
	if len(sources) != 0 {
		t.Fatal("missing source added")
	}
	backupAddSource(&sources, dir, "temp", "folder")
	backupAddSource(&sources, dir, "temp", "folder")
	if len(sources) != 1 || sources[0].Path != dir || sources[0].Label != "temp" {
		t.Fatalf("unexpected sources: %#v", sources)
	}
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	backupAddSource(&sources, file, "file", "folder")
	if len(sources) != 1 {
		t.Fatal("file source added")
	}
}

func TestBackupBrowse(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "b"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "a"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	got := (&Agent{}).BackupBrowse(dir)
	if len(got) != 2 || got[0].Label != "a" || got[1].Label != "b" {
		t.Fatalf("unexpected browse result: %#v", got)
	}
	if got := (&Agent{}).BackupBrowse(filepath.Join(dir, "missing")); got != nil {
		t.Fatalf("missing path returned entries: %#v", got)
	}
}

func TestBackupProgressDue(t *testing.T) {
	last := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	if backupProgressDue(last.Add(4*time.Second), last) {
		t.Fatal("progress reported too early")
	}
	if !backupProgressDue(last.Add(5*time.Second), last) {
		t.Fatal("progress not reported after interval")
	}
}

func TestBackupSkippableError(t *testing.T) {
	if !backupSkippableError(os.ErrPermission) {
		t.Fatal("permission error should be skippable")
	}
	if !backupSkippableError(errors.Join(os.ErrNotExist, errors.New("gone"))) {
		t.Fatal("not-exist error should be skippable")
	}
	if backupSkippableError(errors.New("upload failed")) {
		t.Fatal("generic error should not be skippable")
	}
}

func TestCancelBackup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	backupCancels.Store(99, cancel)
	defer backupCancels.Delete(99)
	if !(&Agent{}).CancelBackup(99) {
		t.Fatal("running backup was not canceled")
	}
	if ctx.Err() == nil {
		t.Fatal("cancel func was not called")
	}
	if (&Agent{}).CancelBackup(100) {
		t.Fatal("missing backup canceled")
	}
}
