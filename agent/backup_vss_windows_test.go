package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/StackExchange/wmi"
	"github.com/go-resty/resty/v2"
	"golang.org/x/sys/windows"
)

// The test executable also acts as Diskshadow's child, just like the agent.
func init() {
	if len(os.Args) == 3 && os.Args[1] == "--backup-vss-helper" {
		if err := BackupVSSHelper(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
}

func TestBackupVSSCancel(t *testing.T) {
	if os.Getenv("QDT_TEST_VSS") != "1" {
		t.Skip("set QDT_TEST_VSS=1")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "source.txt")
	if err := os.WriteFile(source, []byte("cancel test"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var result backupSnapshot
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var body struct {
			Snapshot *backupSnapshot `json:"vss_result"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Snapshot != nil {
			result = *body.Snapshot
			if result.Status == "reading" {
				cancel()
			}
		}
		w.Write([]byte(`"ok"`))
	}))
	defer server.Close()
	a := &Agent{ProgramDir: dir, rClient: resty.New()}
	_, err := a.runBackup(ctx, BackupJob{ID: 1, RepoID: "00000000-0000-0000-0000-000000000001", VSSMode: "required", Paths: []string{source}, Endpoint: server.URL, BlobURL: server.URL, ManifestURL: server.URL}, time.Now().UTC())
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancel result:", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if result.Status != "failed" || len(result.Volumes) != 1 {
		t.Fatal("missing VSS cancellation result", result)
	}
	var shadows []struct{ ID string }
	if err = wmi.Query("SELECT ID FROM Win32_ShadowCopy", &shadows); err != nil {
		t.Fatal(err)
	}
	for _, s := range shadows {
		for _, v := range result.Volumes {
			if s.ID == v.ID {
				t.Fatal("snapshot survived cancellation")
			}
		}
	}
	t.Log("Canceled immediately after snapshot creation; owned snapshot released before return")
}

func TestBackupVSSCrashChild(t *testing.T) {
	dir := os.Getenv("QDT_VSS_CRASH_DIR")
	if dir == "" {
		t.Skip("child process only")
	}
	snapshot, _, cleanup, err := (&Agent{ProgramDir: dir}).backupVSS(context.Background(), []string{filepath.Join(dir, "source.txt")})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	raw, _ := json.Marshal(snapshot)
	if err = os.WriteFile(filepath.Join(dir, "crash-ready.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Minute)
}

func TestBackupVSSCrashCleanup(t *testing.T) {
	if os.Getenv("QDT_TEST_VSS") != "1" {
		t.Skip("set QDT_TEST_VSS=1")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "source.txt"), []byte("crash test"), 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestBackupVSSCrashChild$", "-test.timeout=140s")
	cmd.Env = append(os.Environ(), "QDT_VSS_CRASH_DIR="+dir)
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	var snapshot backupSnapshot
	deadline := time.Now().Add(125 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(filepath.Join(dir, "crash-ready.json"))
		if err == nil && json.Unmarshal(raw, &snapshot) == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if len(snapshot.Volumes) == 0 {
		t.Fatal("child snapshot did not become ready")
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	for attempt := 0; attempt < 50; attempt++ {
		var shadows []struct{ ID string }
		if err = wmi.Query("SELECT ID FROM Win32_ShadowCopy", &shadows); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, s := range shadows {
			for _, v := range snapshot.Volumes {
				if s.ID == v.ID {
					found = true
				}
			}
		}
		if !found {
			t.Log("Agent process killed; Windows released all owned volatile shadows")
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("snapshot survived requester crash")
}

func TestBackupVSSWindows(t *testing.T) {
	if os.Getenv("QDT_TEST_VSS") != "1" {
		t.Skip("set QDT_TEST_VSS=1 to create a disposable local VSS snapshot")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "locked.txt")
	if err := os.WriteFile(source, []byte("before snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	path, _ := windows.UTF16PtrFromString(source)
	// No sharing: a normal backup cannot read this file while it is in use.
	handle, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	var before []struct{ ID string }
	if err = wmi.Query("SELECT ID FROM Win32_ShadowCopy", &before); err != nil {
		t.Fatal(err)
	}
	agent := &Agent{ProgramDir: dir}
	snapshot, roots, cleanup, err := agent.backupVSS(context.Background(), []string{source})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	})
	if len(snapshot.Volumes) != 1 || len(roots) != 1 {
		t.Fatal("incomplete snapshot")
	}
	var written uint32
	if err = windows.WriteFile(handle, []byte("after snapshot!"), &written, nil); err != nil {
		t.Fatal(err)
	}
	if err = windows.FlushFileBuffers(handle); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(roots[0].Read)
	if err != nil || string(raw) != "before snapshot" {
		t.Fatalf("snapshot file mismatch: %q %v", raw, err)
	}
	if err = cleanup(); err != nil {
		t.Fatal(err)
	}
	var after []struct{ ID string }
	if err = wmi.Query("SELECT ID FROM Win32_ShadowCopy", &after); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, s := range after {
		ids[s.ID] = true
	}
	for _, s := range snapshot.Volumes {
		if ids[s.ID] {
			t.Fatal("owned shadow remained after cleanup")
		}
	}
	for _, s := range before {
		if !ids[s.ID] {
			t.Fatal("foreign shadow disappeared")
		}
	}
	t.Log("Exclusive-open file read from snapshot; later live modification excluded; owned snapshot removed; foreign snapshots preserved")
}
