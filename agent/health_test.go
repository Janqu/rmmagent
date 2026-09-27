package agent

import (
	"path/filepath"
	"testing"
)

func TestDirWritable(t *testing.T) {
	if !dirWritable(t.TempDir()) {
		t.Fatal("temp dir should be writable")
	}
	if dirWritable(filepath.Join(t.TempDir(), "missing")) {
		t.Fatal("missing dir should not be writable")
	}
}
