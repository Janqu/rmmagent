package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/go-resty/resty/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupLANDirectCopyAndIsolation(t *testing.T) {
	repo := "00000000-0000-0000-0000-000000000001"
	lease := "00000000-0000-0000-0000-000000000002"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	target := t.TempDir()
	reply := backupLANReceive(map[string]string{"address": address, "path": target, "repo": repo, "run": "1", "token": lease})
	if reply["ok"] != true {
		t.Fatal(reply)
	}
	fingerprint := reply["fingerprint"].(string)
	client, err := backupLANClient(address, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	ctx := context.Background()
	defer backupLANRequest(ctx, client, address, lease, http.MethodPost, "finish", "", nil)
	if code, err := backupLANRequest(ctx, client, address, "wrong", http.MethodGet, "probe", "", nil); err != nil || code != 401 {
		t.Fatalf("unauthorized: %d %v", code, err)
	}
	bad, _ := backupLANClient(address, strings.Repeat("0", 64))
	defer bad.CloseIdleConnections()
	if _, err := backupLANRequest(ctx, bad, address, lease, http.MethodGet, "probe", "", nil); err == nil {
		t.Fatal("wrong certificate trusted")
	}
	if code, err := backupLANRequest(ctx, client, address, lease, http.MethodPut, "manifests/2", strings.Repeat("a", 64), []byte("bad")); err != nil || code != 404 {
		t.Fatalf("cross-run write: %d %v", code, err)
	}
	id := strings.Repeat("a", 64)
	body := []byte("encrypted cached block")
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	if code, err := backupLANRequest(ctx, client, address, lease, http.MethodPut, "blobs/"+id, hash, []byte("corrupt")); err != nil || code != 422 {
		t.Fatalf("corruption: %d %v", code, err)
	}
	source := &Agent{ProgramDir: t.TempDir(), rClient: resty.New()}
	cache, err := source.backupLANCache(repo)
	if err != nil {
		t.Fatal(err)
	}
	if err := backupReplicaWrite(cache, id, body); err != nil {
		t.Fatal(err)
	}
	cache.Close()
	// The RMM server exposes inventory and the encrypted manifest only. Cached file data must stay on LAN.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "objects/"):
			json.NewEncoder(w).Encode([]backupReplicaObject{{ID: id, Size: len(body), SHA256: hash}})
		case strings.HasSuffix(r.URL.Path, "manifest/"):
			w.Write([]byte("encrypted manifest"))
		default:
			t.Error("LAN copy fetched cached block via RMM")
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	job := backupReplicaJob{RunID: 1, RepoID: repo, Lease: lease, LanAddress: address, Fingerprint: fingerprint}
	copied, err := source.backupLANCopy(ctx, job, server.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	if copied != int64(len(body)+len("encrypted manifest")) {
		t.Fatal(copied)
	}
	actual, err := os.ReadFile(filepath.Join(target, "qdt-backup", repo, "blobs", id))
	if err != nil || string(actual) != string(body) {
		t.Fatal("LAN data differs", err)
	}
	if _, err := os.Stat(filepath.Join(target, "qdt-backup", repo, "manifests", "1")); err != nil {
		t.Fatal(err)
	}
	if _, err := backupLANClient("8.8.8.8:9447", fingerprint); err == nil {
		t.Fatal("public endpoint accepted")
	}
}
