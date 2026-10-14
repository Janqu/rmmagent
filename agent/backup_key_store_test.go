package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBackupKeyPreparationAndProtection(t *testing.T) {
	a := &Agent{ProgramDir: t.TempDir()}
	repo := "00000000-0000-0000-0000-000000000009"
	input := map[string]string{"operation": "prepare", "password": "test-recovery-password"}
	pack, err := a.backupKeyOperation(repo, input)
	if err != nil {
		t.Fatal(err)
	}
	key, err := a.backupRepoKey(repo, false)
	if err != nil {
		t.Fatal(err)
	}
	next, err := a.backupKeyOperation(repo, input)
	if err != nil || next == pack {
		t.Fatal("prepare retry failed", err)
	}
	same, err := a.backupRepoKey(repo, false)
	if err != nil || !bytes.Equal(key, same) {
		t.Fatal("prepare replaced the existing data key", err)
	}
	path := filepath.Join(a.ProgramDir, "backup", repo+".key")
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" && bytes.Contains(stored, key) {
		t.Fatal("Windows key stored in plaintext")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("key permissions", err)
		}
		info, err = os.Stat(filepath.Dir(path))
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatal("directory permissions", err)
		}
	}
	if strings.Contains(pack, input["password"]) {
		t.Fatal("password persisted in recovery package")
	}
	replacement := &Agent{ProgramDir: t.TempDir()}
	if _, err := replacement.backupKeyOperation(repo, map[string]string{"operation": "import", "password": input["password"], "package": pack}); err != nil {
		t.Fatal(err)
	}
	recovered, err := replacement.backupRepoKey(repo, false)
	if err != nil || !bytes.Equal(key, recovered) {
		t.Fatal("recovery changed the key", err)
	}
	// Legacy raw keys are migrated without changing the key or replacing corruption.
	legacy := &Agent{ProgramDir: t.TempDir()}
	dir := filepath.Join(legacy.ProgramDir, "backup")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, repo+".key")
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := legacy.backupRepoKey(repo, true)
	if err != nil || !bytes.Equal(key, got) {
		t.Fatal("legacy key lost", err)
	}
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.backupRepoKey(repo, true); err == nil {
		t.Fatal("corrupt key silently replaced")
	}
}
