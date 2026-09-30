package agent

import (
	"os"
	"testing"
)

func TestBackupTreeAndDestination(t *testing.T) {
	manifest := backupManifest{Files: []backupManifestFile{{Path: "/data/team/a.txt", Size: 1}, {Path: "/data/team/b.txt", Size: 2}, {Path: "/data/readme.txt", Size: 3}}}
	result := backupBrowseManifest(manifest, map[string]string{"view": "tree", "folder": "/data", "offset": "0"})
	entries := result["files"].([]map[string]interface{})
	if len(entries) != 2 || entries[0]["path"] != "/data/team" || entries[0]["kind"] != "directory" {
		t.Fatalf("tree: %+v", result)
	}
	result = backupBrowseManifest(manifest, map[string]string{"view": "tree", "folder": "/data", "query": "a.txt", "offset": "0"})
	if result["total"] != 1 {
		t.Fatalf("search: %+v", result)
	}
	root := t.TempDir()
	result = backupDestinationCheck(root)
	if result["ok"] != true {
		t.Fatal(result)
	}
	files, err := os.ReadDir(root)
	if err != nil || len(files) != 0 {
		t.Fatalf("write-check cleanup: %v %v", files, err)
	}
	if backupDestinationCheck("relative")["error"] == nil {
		t.Fatal("relative storage accepted")
	}
}
