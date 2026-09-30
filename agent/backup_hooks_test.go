//go:build !windows

package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/sirupsen/logrus"
)

func TestBackupHooksLifecycle(t *testing.T) {
	for _, mode := range []string{"success", "pre-abort", "pre-continue", "post-fail", "backup-fail", "post-success-only", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			file, after := filepath.Join(root, "source.txt"), filepath.Join(root, "after.txt")
			logger := logrus.New()
			logger.SetOutput(io.Discard)
			var mu sync.Mutex
			objects := map[string][]byte{}
			var final map[string]any
			a := &Agent{ProgramDir: filepath.Join(root, "agent"), UnixTmpDir: root, rClient: resty.New(), Logger: logger}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.URL.Path == "/status/" {
					if err := json.NewDecoder(r.Body).Decode(&final); err != nil {
						t.Error(err)
					}
					if mode == "cancel" {
						cancel()
					}
					w.Write([]byte(`"ok"`))
					return
				}
				if mode == "backup-fail" || mode == "post-success-only" {
					w.WriteHeader(500)
					return
				}
				if r.Method == "PUT" {
					objects[r.URL.Path], _ = io.ReadAll(r.Body)
					w.WriteHeader(201)
					return
				}
				if data, ok := objects[r.URL.Path]; ok {
					w.Write(data)
				} else {
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			pre := &BackupScript{ScriptID: 1, Name: "prepare", Shell: "shell", Timeout: 3, Code: "#!/bin/sh\nprintf 'prepared' > \"$1\"\n", Args: []string{file}}
			post := &BackupScript{ScriptID: 2, Name: "cleanup", Shell: "shell", Timeout: 3, Code: "#!/bin/sh\nprintf '%s:%s' \"$QDT_BACKUP_PHASE\" \"$QDT_BACKUP_STATUS\" > \"$1\"\n", Args: []string{after}}
			hooks := &BackupHooks{Pre: pre, Post: post, PreFailure: "abort", PostWhen: "always"}
			if strings.HasPrefix(mode, "pre-") {
				pre.Code += "exit 7\n"
			}
			if mode == "pre-continue" {
				hooks.PreFailure = "continue"
			}
			if mode == "post-fail" {
				post.Code += "exit 9\n"
			}
			if mode == "post-success-only" {
				hooks.PostWhen = "success"
			}
			job := BackupJob{ID: 1, ProfileID: 1, RepoID: "00000000-0000-0000-0000-000000000001", Hooks: hooks, Paths: []string{file}, ChunkBytes: 1024, Endpoint: server.URL + "/status/", BlobURL: server.URL + "/blobs/", ManifestURL: server.URL + "/manifest/"}
			_, results, err := a.runBackupWithHooks(ctx, job, time.Now().UTC())
			wantSuccess := mode == "success" || mode == "pre-continue" || mode == "post-fail"
			if (err == nil) != wantSuccess {
				t.Fatalf("backup outcome: %v", err)
			}
			if len(results) != 2 {
				t.Fatalf("results: %+v", results)
			}
			if mode == "post-success-only" {
				if _, err := os.Stat(after); !os.IsNotExist(err) || results[1].Status != "skipped" {
					t.Fatal("post ran on failed backup")
				}
			} else {
				want := "post:failed"
				if wantSuccess {
					want = "post:success"
				}
				if mode == "cancel" {
					want = "post:canceled"
				}
				if data, err := os.ReadFile(after); err != nil || string(data) != want {
					t.Fatalf("post: %q %v", data, err)
				}
			}
			if (mode == "pre-continue" || mode == "post-fail") && backupHookWarning(results) == "" {
				t.Fatal("missing warning")
			}
			if wantSuccess {
				job.Hooks = nil
				targetRoot, _, _, err := a.restoreSnapshot(context.Background(), job)
				if err != nil {
					t.Fatal(err)
				}
				target, err := backupRestorePath(targetRoot, file)
				if err != nil {
					t.Fatal(err)
				}
				if data, err := os.ReadFile(target); err != nil || string(data) != "prepared" {
					t.Fatalf("backup did not capture pre-script output: %q %v", data, err)
				}
			}
		})
	}
}
