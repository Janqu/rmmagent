package agent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
)

func TestBackupSnapshotPathMapping(t *testing.T) {
	root := backupReadRoot{Original: filepath.Join(t.TempDir(), "source"), Read: filepath.Join(t.TempDir(), "snapshot")}
	path, err := backupOriginalPath(root, filepath.Join(root.Read, "sub", "file.txt"))
	if err != nil || path != filepath.Join(root.Original, "sub", "file.txt") {
		t.Fatal(path, err)
	}
	if _, err := backupOriginalPath(root, filepath.Join(root.Read, "..", "outside")); err == nil {
		t.Fatal("accepted snapshot escape")
	}
	if _, err := (&Agent{}).runBackup(context.Background(), BackupJob{VSSMode: "unknown"}, time.Now()); err == nil {
		t.Fatal("accepted unknown snapshot mode")
	}
	if runtime.GOOS != "windows" {
		if _, err := (&Agent{}).runBackup(context.Background(), BackupJob{VSSMode: "required", Paths: []string{os.TempDir()}}, time.Now()); err == nil {
			t.Fatal("VSS silently fell back on non-Windows")
		}
	}
}

func TestBackupSnapshotOriginalPathsAndRestore(t *testing.T) {
	root := t.TempDir()
	original, snapshot := filepath.Join(root, "original"), filepath.Join(root, "snapshot")
	if err := os.Mkdir(snapshot, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"keep.txt", "skip.tmp"} {
		if err := os.WriteFile(filepath.Join(snapshot, name), []byte("snapshot content"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	objects := map[string][]byte{}
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/status/" {
			w.Write([]byte(`"ok"`))
			return
		}
		if r.Method == "PUT" {
			objects[r.URL.Path], _ = io.ReadAll(r.Body)
			w.WriteHeader(201)
			return
		}
		if raw, ok := objects[r.URL.Path]; ok {
			w.Write(raw)
		} else {
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	a := &Agent{ProgramDir: filepath.Join(root, "agent"), rClient: resty.New()}
	job := BackupJob{ID: 1, RepoID: "00000000-0000-0000-0000-000000000001", ChunkBytes: 1024, Endpoint: server.URL + "/status/", BlobURL: server.URL + "/blobs/", ManifestURL: server.URL + "/manifest/", Excludes: []string{filepath.Join(original, "skip.tmp")}, readRoots: []backupReadRoot{{Original: original, Read: snapshot}}, snapshot: &backupSnapshot{Mode: "required", Status: "reading", CreatedAt: time.Now().UTC()}}
	stats, err := a.runBackupData(context.Background(), job, time.Now().UTC())
	if err != nil || stats.Files != 1 {
		t.Fatal(stats, err)
	}
	target, _, _, err := a.restoreSnapshot(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := backupRestorePath(target, filepath.Join(original, "keep.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(restored); err != nil || string(raw) != "snapshot content" {
		t.Fatalf("restore original path: %q %v", raw, err)
	}
}
