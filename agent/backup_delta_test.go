package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
)

func TestBackupDeltaEndToEnd(t *testing.T) {
	var mu sync.Mutex
	blobs, manifests := map[string][]byte{}, map[string][]byte{}
	var latest []byte
	lookups, uploads, downloads := 0, 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/status/":
			w.Write([]byte(`"ok"`))
		case r.URL.Path == "/previous/":
			if latest == nil {
				w.WriteHeader(404)
			} else {
				w.Write(latest)
			}
		case r.URL.Path == "/check/":
			lookups++
			var in struct {
				IDs []string `json:"blob_ids"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if len(in.IDs) > 128 {
				t.Error("unbounded blob lookup")
			}
			found := []string{}
			for _, id := range in.IDs {
				if _, ok := blobs[id]; ok {
					found = append(found, id)
				}
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"existing": found})
		case strings.HasPrefix(r.URL.Path, "/manifest/"):
			if r.Method == "PUT" {
				data, _ := io.ReadAll(r.Body)
				manifests[r.URL.Path] = data
				latest = data
				w.WriteHeader(201)
			} else {
				w.Write(manifests[r.URL.Path])
			}
		case strings.HasPrefix(r.URL.Path, "/blobs/"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/blobs/"), "/")
			if r.Method == "PUT" {
				data, _ := io.ReadAll(r.Body)
				blobs[id] = data
				uploads++
				w.WriteHeader(201)
			} else if data, ok := blobs[id]; ok {
				downloads++
				w.Write(data)
			} else {
				w.WriteHeader(404)
			}
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	input := filepath.Join(root, "input")
	if err := os.Mkdir(input, 0700); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 8<<20)
	rand.New(rand.NewSource(31)).Read(data)
	for _, name := range []string{"a.bin", "duplicate.bin"} {
		if err := os.WriteFile(filepath.Join(input, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	compressed := bytes.Repeat([]byte("compressible backup data\n"), 50000)
	if err := os.WriteFile(filepath.Join(input, "compress.txt"), compressed, 0600); err != nil {
		t.Fatal(err)
	}
	a := &Agent{ProgramDir: filepath.Join(root, "agent"), Hostname: "test", rClient: resty.New()}
	job := BackupJob{ID: 1, RepoID: "00000000-0000-0000-0000-000000000001", Paths: []string{input, input}, ChunkBytes: 8 << 20, Endpoint: server.URL + "/status/", BlobURL: server.URL + "/blobs/", ManifestURL: server.URL + "/manifest/1/", CheckURL: server.URL + "/check/", PreviousManifestURL: server.URL + "/previous/"}
	first, err := a.runBackup(context.Background(), job, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if first.Files != 3 || first.Reused < int64(len(data)) || first.Uploaded > int64(len(data))+(256<<10) {
		t.Fatalf("first backup did not deduplicate/compress: %+v", first)
	}
	initialUploads := uploads
	job.ID = 2
	job.ManifestURL = server.URL + "/manifest/2/"
	second, err := a.runBackup(context.Background(), job, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if second.Unchanged != 3 || second.Reused != second.Total || second.ChunksUploaded != 0 || uploads != initialUploads {
		t.Fatalf("unchanged backup uploaded content: %+v", second)
	}
	changed := append(bytes.Clone(data[:1024]), bytes.Repeat([]byte{0x7e}, 317)...)
	changed = append(changed, data[1024:len(data)-97]...)
	copy(changed[4<<20:], []byte("seventeen-changes!"))
	if err := os.WriteFile(filepath.Join(input, "a.bin"), changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(input, "duplicate.bin")); err != nil {
		t.Fatal(err)
	}
	job.ID = 3
	job.ManifestURL = server.URL + "/manifest/3/"
	third, err := a.runBackup(context.Background(), job, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if third.Files != 2 || third.Uploaded > 2<<20 || third.Reused < 6<<20 {
		t.Fatalf("small edits retransmitted the file: %+v", third)
	}
	restoreRoot, _, _, err := a.restoreSnapshot(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]byte{"a.bin": changed, "compress.txt": compressed} {
		target, err := backupRestorePath(restoreRoot, filepath.Join(input, name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(target)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("restore %s differs: %v", name, err)
		}
	}

	listing := a.backupInspect(job, map[string]string{"operation": "list", "query": "compress", "offset": "0"})
	if listing["total"] != 1 {
		t.Fatalf("search: %+v", listing)
	}
	preview := a.backupInspect(job, map[string]string{"operation": "content", "path": filepath.Join(input, "compress.txt"), "offset": "0"})
	encoded, ok := preview["data"].(string)
	if !ok {
		t.Fatalf("preview: %+v", preview)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || !bytes.Equal(decoded, compressed[:512<<10]) {
		t.Fatal("preview differs", err)
	}

	mu.Lock()
	beforeDownloads := downloads
	mu.Unlock()
	ranged := a.backupInspect(job, map[string]string{"operation": "content", "path": filepath.Join(input, "a.bin"), "offset": "7340032"})
	encoded, ok = ranged["data"].(string)
	if !ok {
		t.Fatalf("range failed: %+v", ranged)
	}
	decoded, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil || !bytes.Equal(decoded, changed[7<<20:(7<<20)+(512<<10)]) {
		t.Fatal("range bytes differ", err)
	}
	mu.Lock()
	rangeDownloads := downloads - beforeDownloads
	mu.Unlock()
	if rangeDownloads > 8 {
		t.Fatalf("range redownloaded preceding chunks: %d", rangeDownloads)
	}
	job.Paths = []string{filepath.Join(input, "compress.txt")}
	selectedRoot, files, _, err := a.restoreSnapshot(context.Background(), job)
	if err != nil || files != 1 {
		t.Fatalf("selective restore %d %v", files, err)
	}
	unexpected, _ := backupRestorePath(selectedRoot, filepath.Join(input, "a.bin"))
	if _, err := os.Stat(unexpected); !os.IsNotExist(err) {
		t.Fatal("restored unselected file")
	}
	job.Paths = []string{input}
	// Losing a stored chunk must invalidate the metadata shortcut and repair it.
	mu.Lock()
	for id := range blobs {
		delete(blobs, id)
		break
	}
	mu.Unlock()
	job.ID = 4
	job.ManifestURL = server.URL + "/manifest/4/"
	if _, err := a.runBackup(context.Background(), job, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := a.runBackupRestore(job); err != nil {
		t.Fatal(err)
	}

 originalProgramDir:=a.ProgramDir
 t.Chdir(originalProgramDir)
 a.ProgramDir=""
 if restored,_,_,err:=a.restoreSnapshot(context.Background(),job);err!=nil || !filepath.IsAbs(restored){t.Fatalf("Unix default restore destination: %q %v",restored,err)}
 a.ProgramDir=originalProgramDir

	transfer, original, err := a.backupSnapshot(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	transfer.known = make(map[string]bool)
	transfer.stats = &backupStats{}
	large := original
	large.Files = nil
	for i := 0; i < 10000; i++ {
		item := original.Files[0]
		item.Path = fmt.Sprintf("/%05d/%s", i, strings.Repeat("long-path", 70))
		large.Files = append(large.Files, item)
	}
	if err := transfer.saveManifest(context.Background(), large); err != nil {
		t.Fatal(err)
	}
	_, decodedManifest, err := a.backupSnapshot(context.Background(), job)
	if err != nil || len(decodedManifest.Files) != 10000 || decodedManifest.Files[9999].Path != large.Files[9999].Path {
		t.Fatal("large multipart manifest differs", err)
	}
	t.Logf("first: %d bytes source, %d uploaded; unchanged: %d uploaded; edited: %d uploaded, %d reused; batch requests: %d", first.Total, first.Uploaded, second.Uploaded, third.Uploaded, third.Reused, lookups)
}

func TestBackupDeltaIntegrityAndLegacy(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	plain := bytes.Repeat([]byte("content"), 10000)
	for _, seal := range []func([]byte, []byte, []byte) ([]byte, error){backupSeal, backupPack} {
		sealed, err := seal(key, []byte("aad"), plain)
		if err != nil {
			t.Fatal(err)
		}
		got, err := backupUnpack(key, []byte("aad"), sealed)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("legacy/new object failed: %v", err)
		}
		sealed[len(sealed)-1] ^= 1
		if _, err := backupUnpack(key, []byte("aad"), sealed); err == nil {
			t.Fatal("tampering accepted")
		}
	}
	a := &Agent{ProgramDir: t.TempDir()}
	repo := "00000000-0000-0000-0000-000000000001"
	if _, err := a.backupRepoKey(repo, false); err == nil {
		t.Fatal("restore created a missing key")
	}
	if _, err := a.backupRepoKey(repo, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(a.ProgramDir, "backup", repo+".key")
	if err := os.WriteFile(path, []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.backupRepoKey(repo, true); err == nil {
		t.Fatal("damaged key replaced")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "damaged" {
		t.Fatal("key was overwritten")
	}
	if _, err := a.backupRepoKey("../escape", true); err == nil {
		t.Fatal("unsafe repository accepted")
	}
}

func BenchmarkBackupDeltaChunking(b *testing.B) {
	data := make([]byte, 8<<20)
	rand.New(rand.NewSource(31)).Read(data)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := backupChunks(context.Background(), bytes.NewReader(data), 8<<20, func([]byte) error { return nil }); err != nil {
			b.Fatal(err)
		}
	}
}
