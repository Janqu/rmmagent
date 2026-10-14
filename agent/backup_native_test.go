//go:build !windows

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
)

func TestBackupDatabaseTimeout(t *testing.T) {
	a := &Agent{ProgramDir: t.TempDir()}
	dir := filepath.Join(a.ProgramDir, "backup")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	credential := filepath.Join(dir, "credentials")
	if err := os.WriteFile(credential, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(t.TempDir(), "dump")
	pidFile := filepath.Join(t.TempDir(), "pid")
	t.Setenv("BACKUP_TEST_PID", pidFile)
	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho $$ > \"$BACKUP_TEST_PID\"\nprintf partial\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"postgresql", "mariadb", "mysql", "mssql"} {
		source := "database://" + kind + "/timeout"
		config := backupNativeConfig{Tool: tool, TimeoutSeconds: 1, ServiceFile: credential, Service: "test", DefaultsFile: credential, Database: "app", Server: "localhost", StagingDir: t.TempDir()}
		data, _ := json.Marshal(map[string]backupNativeConfig{source: config})
		if err := os.WriteFile(filepath.Join(dir, "native-sources.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		_, _, err := a.backupNativeArchive(context.Background(), source, nil)
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 5*time.Second {
			t.Fatalf("%s: timeout not enforced: %v", kind, err)
		}
		pidData, err := os.ReadFile(pidFile)
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Fatalf("%s: export process still exists: %v", kind, err)
		}
		entries, err := os.ReadDir(config.StagingDir)
		if err != nil || len(entries) != 0 {
			t.Fatal("partial export retained", entries, err)
		}
		for _, invalid := range []int{-1, 86401} {
			config.TimeoutSeconds = invalid
			if err := backupNativeValidate(source, config); err == nil {
				t.Fatal("invalid timeout accepted", invalid)
			}
		}
	}
}

func TestBackupNativeExportAndRestore(t *testing.T) {
	a := &Agent{ProgramDir: t.TempDir(), Hostname: "native-test", rClient: resty.New()}
	configDir := filepath.Join(a.ProgramDir, "backup")
	if err := os.Mkdir(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	credential := filepath.Join(configDir, "credentials")
	if err := os.WriteFile(credential, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	tool := filepath.Join(bin, "zfs")
	writeTool := func(script string) {
		t.Helper()
		if err := os.WriteFile(tool, []byte("#!/bin/sh\nset -eu\n"+script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig := func(source string) {
		t.Helper()
		data, _ := json.Marshal(map[string]backupNativeConfig{source: {Tool: tool, ServiceFile: credential, Service: "test", DefaultsFile: credential, Database: "customer"}})
		if err := os.WriteFile(filepath.Join(configDir, "native-sources.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
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
	defer server.Close()
	for _, source := range []string{"database://postgresql/app", "database://mariadb/app", "database://mysql/app", "zfs://tank/data"} {
		t.Run(source, func(t *testing.T) {
			writeConfig(source)
			log := filepath.Join(t.TempDir(), "commands")
			t.Setenv("NATIVE_TEST_LOG", log)
			writeTool(`printf '%s\n' "$*" >> "$NATIVE_TEST_LOG"
case "$1" in
 snapshot|destroy) exit 0 ;;
 send) [ "$2" = -w ] && [ "$3" = -p ] ;;
 --no-password) [ "$2" = --format=custom ] && [ "$3" = --dbname=service=test ] && [ -f "$PGSERVICEFILE" ] ;;
 --defaults-file=*) [ "$2" = --lock-all-tables ] ;;
 *) exit 3 ;;
esac
printf 'native archive content'
`)
			job := BackupJob{ID: 1, RepoID: "00000000-0000-0000-0000-000000000001", Paths: []string{source}, Excludes: []string{"*"}, ChunkBytes: 1024, Endpoint: server.URL + "/status/", BlobURL: server.URL + "/blobs/", ManifestURL: server.URL + "/manifest/"}
			stats, err := a.runBackupData(context.Background(), job, time.Now().UTC())
			if err != nil || stats.Files != 1 {
				t.Fatal(stats, err)
			}
			restoreJob := job
			restoreJob.Paths = nil
			dest, count, _, err := a.restoreSnapshot(context.Background(), restoreJob)
			if err != nil || count != 1 {
				t.Fatal(count, err)
			}
			found := false
			if err := filepath.WalkDir(dest, func(path string, e os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !e.IsDir() {
					data, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					found = bytes.Equal(data, []byte("native archive content"))
				}
				return nil
			}); err != nil || !found {
				t.Fatal("restored export differs", err)
			}
			entries, err := os.ReadDir(filepath.Join(configDir, "native-staging"))
			if err != nil || len(entries) != 0 {
				t.Fatal("staging leaked", entries, err)
			}
			if strings.HasPrefix(source, "zfs:") {
				commands, _ := os.ReadFile(log)
				lines := strings.Split(strings.TrimSpace(string(commands)), "\n")
				if len(lines) != 3 || !strings.HasPrefix(lines[0], "snapshot tank/data@qdt-export-") || lines[2] != strings.Replace(lines[0], "snapshot ", "destroy ", 1) {
					t.Fatal("snapshot ownership", string(commands))
				}
			}
		})
	}
	source := "database://postgresql/app"
	// SQL Server creates the file itself; verify authentication and escaped T-SQL.
	sqlSource := "database://mssql/app"
	sqlConfig, _ := json.Marshal(map[string]backupNativeConfig{sqlSource: {
		Tool: tool, Server: "localhost", Database: "erp]archive", Username: "backup_user",
		PasswordFile: credential, StagingDir: t.TempDir(),
	}})
	if err := os.WriteFile(filepath.Join(configDir, "native-sources.json"), sqlConfig, 0600); err != nil {
		t.Fatal(err)
	}
	writeTool(`test "$SQLCMDPASSWORD" = secret
while [ "$#" -gt 0 ]; do
 case "$1" in
  -Q) query="$2"; shift ;;
  -P) exit 8 ;;
 esac
 shift
done
case "$query" in
 *'BACKUP DATABASE [erp]]archive]'*'COPY_ONLY, CHECKSUM; RESTORE VERIFYONLY'*'WITH CHECKSUM;'*) ;;
 *) exit 9 ;;
esac
path=$(printf '%s' "$query" | sed -n "s/.*TO DISK = N'\([^']*\)'.*/\1/p")
printf 'sql native backup' > "$path"
`)
	root, cleanup, err := a.backupNativeArchive(context.Background(), sqlSource, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(root.Read)
	if err != nil || string(data) != "sql native backup" {
		t.Fatal(root, err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	// A failed send must still destroy its own snapshot and remove partial staging.
	log := filepath.Join(t.TempDir(), "zfs-commands")
	t.Setenv("NATIVE_TEST_LOG", log)
	writeTool(`printf '%s\n' "$*" >> "$NATIVE_TEST_LOG"
case "$1" in send) printf partial; exit 1 ;; esac
`)
	if _, _, err := a.backupNativeArchive(context.Background(), "zfs://tank/data", nil); err == nil {
		t.Fatal("failed send accepted")
	}
	commands, _ := os.ReadFile(log)
	if !strings.Contains(string(commands), "destroy tank/data@qdt-export-") {
		t.Fatal("failed send leaked snapshot", string(commands))
	}
	writeConfig(source)
	for _, script := range []string{"echo secret >&2; exit 1", "exit 0"} {
		writeTool(script)
		_, _, err := a.backupNativeArchive(context.Background(), source, nil)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("failure or secret handling", err)
		}
	}
	writeTool("exec sleep 30")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := a.backupNativeArchive(ctx, source, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cancel failed", err)
	}
	if err := os.Chmod(credential, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.backupNativeArchive(context.Background(), source, nil); err == nil {
		t.Fatal("accepted public credentials")
	}
	for _, path := range []string{"zfs://tank/../other", "zfs://tank/data@snapshot", "zfs://tank/data;id", "database://postgresql/user:secret@app", "image://windows/../system"} {
		if _, _, err := a.backupNativeArchive(context.Background(), path, nil); err == nil {
			t.Fatal("accepted invalid source", path)
		}
	}
}

func TestBackupNativeDiscoveryProblems(t *testing.T) {
	a := &Agent{ProgramDir: t.TempDir()}
	dir := filepath.Join(a.ProgramDir, "backup")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	credential := filepath.Join(dir, "service.conf")
	if err := os.WriteFile(credential, []byte("secret-connection-value"), 0600); err != nil {
		t.Fatal(err)
	}
	tool, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source := "database://postgresql/customer"
	config := backupNativeConfig{Tool: tool, ServiceFile: credential, Service: "erp", Label: "Kundenverwaltung"}
	writeConfig := func(c backupNativeConfig) {
		t.Helper()
		data, _ := json.Marshal(map[string]backupNativeConfig{source: c})
		if err := os.WriteFile(filepath.Join(dir, "native-sources.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	findSource := func() BackupSource {
		t.Helper()
		for _, entry := range a.backupNativeSources() {
			if entry.Path == source {
				return entry
			}
		}
		t.Fatal("configured source silently hidden")
		return BackupSource{}
	}
	writeConfig(config)
	if entry := findSource(); entry.Problem != "" || entry.Label != config.Label {
		t.Fatal(entry)
	}
	if err := os.Chmod(credential, 0644); err != nil {
		t.Fatal(err)
	}
	entry := findSource()
	if entry.Problem == "" || strings.Contains(entry.Problem, "secret-connection-value") {
		t.Fatal(entry)
	}
	_, _, exportErr := a.backupNativeArchive(context.Background(), source, nil)
	if exportErr == nil || exportErr.Error() != entry.Problem {
		t.Fatal("discovery and export disagree", entry, exportErr)
	}
	if _, err := os.Stat(filepath.Join(dir, "native-staging")); !os.IsNotExist(err) {
		t.Fatal("invalid configuration created staging", err)
	}
	if err := os.Chmod(credential, 0600); err != nil {
		t.Fatal(err)
	}
	config.Tool = filepath.Join(dir, "missing-tool")
	writeConfig(config)
	if entry := findSource(); entry.Problem == "" {
		t.Fatal("missing tool not explained")
	}
	for _, raw := range []string{
		`{"database://postgresql/customer":{"servcie":"secret-connection-value"}}`,
		`{} {"password":"secret-connection-value"}`, `null`,
		`{"database://postgresql/user:secret-connection-value@host":{}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, "native-sources.json"), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		entries := a.backupNativeSources()
		found := false
		for _, entry := range entries {
			if strings.Contains(entry.Path+entry.Label+entry.Problem, "secret-connection-value") {
				t.Fatal("configuration contents leaked")
			}
			if entry.Kind == "notice" && entry.Problem != "" {
				found = true
			}
		}
		if !found {
			t.Fatal("invalid config has no diagnostic", raw)
		}
	}
}
