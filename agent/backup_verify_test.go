package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-resty/resty/v2"
)

func TestBackupVerifySnapshot(t *testing.T) {
	for _, mode := range []string{"valid", "tampered", "missing", "wrong-size", "wrong-index", "wrong-run", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			a := &Agent{ProgramDir: t.TempDir(), rClient: resty.New()}
			repo := "00000000-0000-0000-0000-000000000001"
			key, err := a.backupRepoKey(repo, true)
			if err != nil {
				t.Fatal(err)
			}
			enc, idkey := backupSubkeys(key, repo)
			plain := []byte("Database archive contents")
			id := backupBlobID(idkey, plain)
			block, err := backupPack(enc, []byte(repo+":"+id), plain)
			if err != nil {
				t.Fatal(err)
			}
			item := backupManifestFile{Path: "native/db.dump", Size: int64(len(plain)), Chunks: []string{id}, ChunkSizes: []int{len(plain)}}
			if mode == "wrong-size" {
				item.Size++
			}
			if mode == "wrong-index" {
				item.ChunkSizes[0]--
			}
			manifest := backupManifest{RepoID: repo, RunID: 1, Files: []backupManifestFile{item}}
			if mode == "wrong-run" {
				manifest.RunID = 2
			}
			raw, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := backupPack(enc, []byte("manifest:"+repo), raw)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "tampered" {
				block[len(block)-1] ^= 1
			}
			reads := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Error("verification wrote to server")
					w.WriteHeader(405)
					return
				}
				if r.URL.Path == "/manifest" {
					w.Write(sealed)
					return
				}
				reads++
				if mode == "missing" {
					w.WriteHeader(404)
					return
				}
				w.Write(block)
			}))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			job := BackupJob{ID: 1, RepoID: repo, ManifestURL: server.URL + "/manifest", BlobURL: server.URL + "/blobs/"}
			files, total, err := a.verifyBackupSnapshot(ctx, job)
			if mode == "valid" {
				if err != nil || files != 1 || total != int64(len(plain)) || reads != 1 {
					t.Fatalf("verification: %d %d %v reads %d", files, total, err, reads)
				}
				replacement := &Agent{ProgramDir: t.TempDir(), rClient: resty.New()}
				if _, _, err := replacement.verifyBackupSnapshot(ctx, job); err == nil {
					t.Fatal("verification succeeded without recovery key")
				}
				password := "test-only-recovery-password"
				pack, err := a.backupKeyOperation(repo, map[string]string{"operation": "export", "password": password})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := replacement.backupKeyOperation(repo, map[string]string{"operation": "import", "password": password, "package": pack}); err != nil {
					t.Fatal(err)
				}
				if _, _, err := replacement.verifyBackupSnapshot(ctx, job); err != nil {
					t.Fatal("replacement verification", err)
				}
				root, count, _, err := replacement.restoreSnapshot(ctx, job)
				if err != nil || count != 1 {
					t.Fatal("replacement restore", err)
				}
				restoredPath, err := backupRestorePath(root, item.Path)
				if err != nil {
					t.Fatal(err)
				}
				contents, err := os.ReadFile(restoredPath)
				if err != nil || !bytes.Equal(contents, plain) {
					t.Fatal("replacement restored different content", err)
				}
			} else if err == nil {
				t.Fatal("corrupt/incomplete backup reported valid")
			}
			if _, err := os.Stat(filepath.Join(a.ProgramDir, "restore")); !os.IsNotExist(err) {
				t.Fatal("verification created restore files")
			}
			got, err := a.backupRepoKey(repo, false)
			if err != nil || !bytes.Equal(got, key) {
				t.Fatal("verification changed key")
			}
		})
	}
}
