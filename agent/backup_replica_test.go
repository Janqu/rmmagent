package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-resty/resty/v2"
)

func TestBackupReplicaRecoveryAndKey(t *testing.T) {
	repo := "00000000-0000-0000-0000-000000000001"
	source := &Agent{ProgramDir: t.TempDir()}
	master, err := source.backupRepoKey(repo, true)
	if err != nil {
		t.Fatal(err)
	}
	enc, key := backupSubkeys(master, repo)
	plain := bytes.Repeat([]byte("recoverable NAS copy\n"), 50000)
	id := backupBlobID(key, plain)
	sealed, err := backupPack(enc, []byte(repo+":"+id), plain)
	if err != nil {
		t.Fatal(err)
	}
	manifest := backupManifest{Format: 2, RunID: 1, RepoID: repo, Files: []backupManifestFile{{Path: "/data/test.txt", Size: int64(len(plain)), Chunks: []string{id}}}}
	raw, _ := json.Marshal(manifest)
	manifestBytes, err := backupPack(enc, []byte("manifest:"+repo), raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(sealed)
	downloads := 0
	damaged := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Backup-Lease") != "lease" {
			t.Error("missing lease")
			w.WriteHeader(403)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "objects/"):
			json.NewEncoder(w).Encode([]backupReplicaObject{{ID: id, Size: len(sealed), SHA256: hex.EncodeToString(sum[:])}})
		case strings.HasSuffix(r.URL.Path, "manifest/"):
			w.Write(manifestBytes)
		case strings.HasSuffix(r.URL.Path, "status/"):
			w.Write([]byte(`"ok"`))
		default:
			downloads++
			if damaged {
				w.Write([]byte("damaged"))
			} else {
				w.Write(sealed)
			}
		}
	}))
	defer server.Close()
	target := &Agent{rClient: resty.New()}
	job := backupReplicaJob{RunID: 1, RepoID: repo, Path: t.TempDir(), Lease: "lease"}
	for i := 0; i < 2; i++ {
		copied, err := target.backupReplicaCopy(context.Background(), job, server.URL+"/")
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 && copied != int64(len(manifestBytes)) {
			t.Fatalf("unchanged copy retransmitted: %d", copied)
		}
	}
	if downloads != 1 {
		t.Fatalf("downloaded %d times", downloads)
	}
	// Restore using only the destination's RPC reader; the primary is not consulted.
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		object := "blobs/" + id
		if r.URL.Path == "/manifest/" {
			object = "manifests/1"
		}
		reply := target.backupReplicaRead(map[string]string{"path": job.Path, "repo": repo, "object": object, "offset": "0"})
		data, ok := reply["data"].(string)
		if !ok {
			t.Error(reply)
			w.WriteHeader(500)
			return
		}
		decoded, _ := base64.StdEncoding.DecodeString(data)
		w.Write(decoded)
	}))
	defer vault.Close()
	source.rClient = resty.New()
	restored, files, _, err := source.restoreSnapshot(context.Background(), BackupJob{ID: 1, RepoID: repo, ManifestURL: vault.URL + "/manifest/", BlobURL: vault.URL + "/blobs/"})
	if err != nil || files != 1 {
		t.Fatalf("NAS restore: %d %v", files, err)
	}
	file, _ := backupRestorePath(restored, "/data/test.txt")
	got, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("NAS restore differs", err)
	}
	// A corrupt local object is repaired; a corrupt transfer never publishes success.
	local := filepath.Join(job.Path, "qdt-backup", repo, "blobs", id)
	if err := os.WriteFile(local, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	damaged = true
	if _, err := target.backupReplicaCopy(context.Background(), job, server.URL+"/"); err == nil {
		t.Fatal("corrupt transfer accepted")
	}
	damaged = false
	if _, err := target.backupReplicaCopy(context.Background(), job, server.URL+"/"); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	linked := filepath.Join(job.Path, "qdt-backup", repo, "blobs", strings.Repeat("b", 64))
	if err := os.Symlink(filepath.Join(outside, "secret"), linked); err != nil {
		t.Fatal(err)
	}
	root, err := backupReplicaRoot(job.Path, repo, false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := root.Open("blobs/" + strings.Repeat("b", 64)); err == nil {
		t.Fatal("symlink escape accepted")
	}
	for _, object := range []string{"../secret", "blobs/../secret", "manifests/-1"} {
		if _, ok := target.backupReplicaRead(map[string]string{"path": job.Path, "repo": repo, "object": object, "offset": "0"})["error"]; !ok {
			t.Fatal("unsafe read accepted")
		}
	}
	// Password-protected recovery package can restore the original key on a replacement install.
	password := "test recovery password"
	wrapped, err := source.backupKeyOperation(repo, map[string]string{"operation": "export", "password": password})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(wrapped, base64.StdEncoding.EncodeToString(master)) {
		t.Fatal("export contains unencrypted key")
	}
	replacement := &Agent{ProgramDir: t.TempDir()}
	input := map[string]string{"operation": "import", "password": "wrong-password-here", "package": wrapped}
	if _, err := replacement.backupKeyOperation(repo, input); err == nil {
		t.Fatal("wrong password accepted")
	}
	input["password"] = password
	if _, err := replacement.backupKeyOperation(repo, input); err != nil {
		t.Fatal(err)
	}
	got, err = replacement.backupRepoKey(repo, false)
	if err != nil || !bytes.Equal(got, master) {
		t.Fatal("key recovery differs", err)
	}
	if err := os.WriteFile(filepath.Join(replacement.ProgramDir, "backup", repo+".key"), bytes.Repeat([]byte{9}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.backupKeyOperation(repo, input); err == nil {
		t.Fatal("different key overwritten")
	}
	// Legacy snapshot objects must remain restorable with the new agent.
	legacy, err := backupSeal(enc, []byte(repo+":"+id), plain)
	if err != nil {
		t.Fatal(err)
	}
	legacyManifest, _ := json.Marshal(backupManifest{RunID: 1, RepoID: repo, Files: manifest.Files})
	legacyManifest, err = backupSeal(enc, []byte("manifest:"+repo), legacyManifest)
	if err != nil {
		t.Fatal(err)
	}
	legacyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manifest/" {
			w.Write(legacyManifest)
		} else {
			w.Write(legacy)
		}
	}))
	defer legacyServer.Close()
	_, count, _, err := source.restoreSnapshot(context.Background(), BackupJob{ID: 1, RepoID: repo, BlobURL: legacyServer.URL + "/blobs/", ManifestURL: legacyServer.URL + "/manifest/"})
	if err != nil || count != 1 {
		t.Fatal(fmt.Sprintf("legacy restore: %d %v", count, err))
	}
}
