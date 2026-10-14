//go:build !windows

package agent

import (
	"context"
	"encoding/json"
	"github.com/go-resty/resty/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReviewNativePathCollision(t *testing.T) {
	a := &Agent{ProgramDir: t.TempDir(), Hostname: "review", rClient: resty.New()}
	dir := filepath.Join(a.ProgramDir, "backup")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	credential := filepath.Join(dir, "pgservice")
	os.WriteFile(credential, []byte("test"), 0600)
	tool := filepath.Join(t.TempDir(), "pg_dump")
	os.WriteFile(tool, []byte("#!/bin/sh\nprintf 'ACTUAL DATABASE BACKUP'\n"), 0700)
	source := "database://postgresql/app"
	data, _ := json.Marshal(map[string]backupNativeConfig{source: {Tool: tool, ServiceFile: credential, Service: "test"}})
	os.WriteFile(filepath.Join(dir, "native-sources.json"), data, 0600)
	unrelated := filepath.Join(t.TempDir(), "backup.dump")
	os.WriteFile(unrelated, []byte("UNRELATED FILE"), 0600)
	objects := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			w.Write([]byte(`"ok"`))
		case "PUT":
			objects[r.URL.Path], _ = io.ReadAll(r.Body)
			w.WriteHeader(201)
		case "HEAD":
			w.WriteHeader(404)
		default:
			w.Write(objects[r.URL.Path])
		}
	}))
	defer server.Close()
	// Models a file source recorded as /native/database/postgresql/app/backup.dump before its DB source.
	virtual := "/native/database/postgresql/app/backup.dump"
	job := BackupJob{ID: 1, RepoID: "00000000-0000-0000-0000-000000000001", Paths: []string{source}, readRoots: []backupReadRoot{{Original: virtual, Read: unrelated}, {Original: source, Read: source}}, ChunkBytes: 1024, Endpoint: server.URL + "/status/", BlobURL: server.URL + "/blobs/", ManifestURL: server.URL + "/manifest/"}
	for _, reverse := range []bool{false, true} {
		objects = map[string][]byte{}
		if reverse {
			job.readRoots[0], job.readRoots[1] = job.readRoots[1], job.readRoots[0]
		}
		_, err := a.runBackupData(context.Background(), job, time.Now().UTC())
		if err == nil || !strings.Contains(err.Error(), "kollidiert") {
			t.Fatalf("order reverse=%v: expected collision, got %v", reverse, err)
		}
		if _, ok := objects["/manifest/"]; ok {
			t.Fatal("collision published a successful manifest")
		}
		entries, err := os.ReadDir(filepath.Join(dir, "native-staging"))
		if err != nil || len(entries) != 0 {
			t.Fatal("staging leak", entries, err)
		}
	}
	// Overlapping ordinary file sources still deduplicate.
	job.readRoots = []backupReadRoot{{Original: virtual, Read: unrelated}, {Original: virtual, Read: unrelated}}
	stats, err := a.runBackupData(context.Background(), job, time.Now().UTC())
	if err != nil || stats.Files != 1 {
		t.Fatal("ordinary file deduplication broken", stats, err)
	}
}
