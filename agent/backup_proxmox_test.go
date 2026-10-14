//go:build !windows

package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
)

func TestBackupProxmoxArchive(t *testing.T) {
	config, staging := t.TempDir(), t.TempDir()
	for _, dir := range []string{"qemu-server", "lxc"} {
		if err := os.Mkdir(filepath.Join(config, dir), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(config, dir, "100.conf"), []byte("hostname: guest\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	sources := backupProxmoxSources(config)
	if len(sources) != 2 || sources[0].Path != "proxmox://qemu/100" || sources[1].Kind != "proxmox_lxc" || !strings.Contains(sources[1].Label, "guest") {
		t.Fatalf("sources: %+v", sources)
	}
	tool := filepath.Join(t.TempDir(), "vzdump")
	writeTool := func(script string) {
		t.Helper()
		if err := os.WriteFile(tool, []byte("#!/bin/sh\nset -eu\n"+script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	assertClean := func() {
		t.Helper()
		entries, err := os.ReadDir(staging)
		if err != nil || len(entries) != 0 {
			t.Fatalf("staging not cleaned: %v %v", entries, err)
		}
	}
	for _, kind := range []string{"qemu", "lxc"} {
		suffix := ".vma.zst"
		if kind == "lxc" {
			suffix = ".tar.zst"
		}
		writeTool(`[ "$1" = 100 ] && [ "$2" = --mode ] && [ "$3" = snapshot ] && [ "$4" = --compress ] && [ "$5" = zstd ] && [ "$6" = --dumpdir ] && [ "$8" = --remove ] && [ "$9" = 0 ]
printf 'guest archive content' > "$7/vzdump-` + kind + `-100-2026_10_02-12_00_00` + suffix + `"
`)
		root, cleanup, err := backupProxmoxArchive(context.Background(), "proxmox://"+kind+"/100", config, staging, tool, nil)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(root.Read)
		if err != nil || string(data) != "guest archive content" || !strings.HasPrefix(root.Original, "/proxmox/"+kind+"/100/") {
			t.Fatal(root, err)
		}
		// Exercise the existing encrypted upload/manifest/download/restore path.
		objects := map[string][]byte{}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost:
				w.Write([]byte(`"ok"`))
			case http.MethodPut:
				objects[r.URL.Path], _ = io.ReadAll(r.Body)
				w.WriteHeader(201)
			case http.MethodHead:
				w.WriteHeader(404)
			default:
				w.Write(objects[r.URL.Path])
			}
		}))
		a := &Agent{ProgramDir: t.TempDir(), Hostname: "pve", rClient: resty.New()}
		job := BackupJob{ID: 1, RepoID: "00000000-0000-0000-0000-000000000001", readRoots: []backupReadRoot{root}, ChunkBytes: 1024, Endpoint: server.URL + "/status/", BlobURL: server.URL + "/blobs/", ManifestURL: server.URL + "/manifest/"}
		stats, err := a.runBackupData(context.Background(), job, time.Now().UTC())
		if err != nil || stats.Files != 1 {
			t.Fatal(stats, err)
		}
		destination, count, _, err := a.restoreSnapshot(context.Background(), job)
		if err != nil || count != 1 {
			t.Fatal(count, err)
		}
		restored, err := os.ReadFile(filepath.Join(destination, strings.TrimPrefix(root.Original, "/")))
		if err != nil || !bytes.Equal(restored, data) {
			t.Fatal("archive restore differs", err)
		}
		server.Close()
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
		assertClean()
	}
	for _, script := range []string{"exit 0", "echo snapshot-failed >&2; exit 1", `touch "$7/vzdump-qemu-100-empty.vma.zst"`, `ln -s /etc/passwd "$7/vzdump-qemu-100-link.vma.zst"`} {
		writeTool(script)
		if _, _, err := backupProxmoxArchive(context.Background(), "proxmox://qemu/100", config, staging, tool, nil); err == nil {
			t.Fatal("accepted incomplete/failed archive", script)
		}
		assertClean()
	}
	for _, source := range []string{"proxmox://qemu/100;touch", "proxmox://lxc/../100", "proxmox://qemu/99", "proxmox://qemu/101", "proxmox://qemu/0100", "proxmox://other/100"} {
		if _, _, err := backupProxmoxArchive(context.Background(), source, config, staging, tool, nil); err == nil {
			t.Fatal("accepted bad or nonlocal guest", source)
		}
	}
	writeTool("exec sleep 30")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, _, err := backupProxmoxArchive(ctx, "proxmox://qemu/100", config, staging, tool, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cancellation", err)
	}
	assertClean()
}
