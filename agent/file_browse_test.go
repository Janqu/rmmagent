package agent

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ugorji/go/codec"
)

func TestFileBrowse(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "note.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "folder"), 0o755); err != nil {
		t.Fatal(err)
	}
	result := fileBrowse(root)
	if result["path"] != root || result["parent"] != filepath.Dir(root) {
		t.Fatalf("bad paths: %#v", result)
	}
	entries := result["entries"].([]fileBrowseEntry)
	if len(entries) != 2 {
		t.Fatalf("entries: %#v", result)
	}
	seen := map[string]fileBrowseEntry{}
	for _, entry := range entries {
		seen[entry.Name] = entry
	}
	if seen["folder"].Type != "dir" || !seen["folder"].IsDir {
		t.Fatalf("folder entry: %#v", seen["folder"])
	}
	if seen["note.txt"].Type != "file" || seen["note.txt"].Size != 5 {
		t.Fatalf("file entry: %#v", seen["note.txt"])
	}
	var raw []byte
	if err := codec.NewEncoderBytes(&raw, new(codec.MsgpackHandle)).Encode(result); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]interface{}
	var handle codec.MsgpackHandle
	handle.MapType = reflect.TypeOf(map[string]interface{}{})
	handle.RawToString = true
	if err := codec.NewDecoderBytes(raw, &handle).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	wireEntries, ok := decoded["entries"].([]interface{})
	if !ok || len(wireEntries) != 2 {
		t.Fatalf("wire entries: %#v", decoded["entries"])
	}
	if _, ok := wireEntries[0].(map[string]interface{}); !ok {
		t.Fatalf("wire entry shape: %#v", wireEntries[0])
	}
}

func TestFileBrowseRejectsInvalidPath(t *testing.T) {
	if got := fileBrowse("bad\x00path"); got["error"] == nil {
		t.Fatal("NUL path accepted")
	}
	if got := fileBrowse(filepath.Join(t.TempDir(), "missing")); got["error"] == nil {
		t.Fatal("missing path accepted")
	}
}

func TestFileRead(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "note.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := fileRead(path)
	if got["name"] != "note.txt" || got["size"] != int64(5) || got["data_base64"] != "aGVsbG8=" {
		t.Fatalf("file read %#v", got)
	}
	if got := fileRead(root); got["error"] == nil {
		t.Fatal("directory accepted")
	}
	if got := fileRead("bad\x00path"); got["error"] == nil {
		t.Fatal("NUL path accepted")
	}
	large := filepath.Join(root, "large.bin")
	if err := os.WriteFile(large, make([]byte, fileReadMaxBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := fileRead(large); got["error"] != "file too large" {
		t.Fatalf("large file response %#v", got)
	}
}
