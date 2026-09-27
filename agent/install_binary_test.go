package agent

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-resty/resty/v2"
)

func TestInstallExecutable(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "download")
	target := filepath.Join(dir, "installed", "agent")
	if err := os.WriteFile(source, []byte("agent-binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := installExecutable(source, target); err != nil {
		t.Fatal(err)
	}
	if err := installExecutable(target, target); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "agent-binary" {
		t.Fatalf("copy failed: %v", err)
	}
	if err := installExecutable(filepath.Join(dir, "missing"), target); err == nil {
		t.Fatal("missing source accepted")
	}
	data, _ = os.ReadFile(target)
	if string(data) != "agent-binary" {
		t.Fatal("failed copy damaged target")
	}
	if !strings.Contains(linuxAgentUnit, "ExecStart="+nixAgentBin+" -m svc") {
		t.Fatal("wrong service executable")
	}
}

func TestVerifySHA256(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "download")
	data := []byte("agent-binary")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(data))
	if err := verifySHA256(path, sum); err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256(path, ""); err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256(path, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong sha256 accepted")
	}
}

func TestDownloadFileAtomicKeepsOldFileOnFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "agent")
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := downloadFileAtomic(resty.New(), "http://127.0.0.1:1/agent", target); err == nil {
		t.Fatal("failed download accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "old" {
		t.Fatalf("target changed to %q", data)
	}
}

func TestReplaceFileWithBackupRollback(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "agent")
	if err := os.WriteFile(target, []byte("old"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := replaceFileWithBackup(filepath.Join(dir, "missing"), target); err == nil {
		t.Fatal("missing replacement accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "old" {
		t.Fatalf("rollback failed, got %q", data)
	}
}
