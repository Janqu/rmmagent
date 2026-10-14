package agent

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const fileReadMaxBytes = 512 << 10

type fileBrowseEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Type  string `json:"type"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
	MTime string `json:"mtime"`
}

func fileBrowse(path string) map[string]interface{} {
	result := map[string]interface{}{"entries": []fileBrowseEntry{}}
	path = strings.TrimSpace(path)
	if strings.ContainsRune(path, 0) {
		result["error"] = "invalid path"
		return result
	}
	if path == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			path = home
		} else {
			path = "."
		}
	}
	path = filepath.Clean(path)
	entries, err := os.ReadDir(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			result["error"] = "path not found"
		} else {
			result["error"] = err.Error()
		}
		return result
	}
	files := make([]fileBrowseEntry, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		kind := "file"
		if entry.IsDir() {
			kind = "dir"
		}
		files = append(files, fileBrowseEntry{
			Name:  entry.Name(),
			Path:  filepath.Join(path, entry.Name()),
			Type:  kind,
			IsDir: entry.IsDir(),
			Size:  info.Size(),
			MTime: info.ModTime().UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	result["path"] = path
	result["parent"] = parentPath(path)
	result["entries"] = files
	return result
}

func parentPath(path string) string {
	parent := filepath.Dir(path)
	if parent == path || parent == "." {
		return ""
	}
	return parent
}

func fileRead(path string) map[string]interface{} {
	result := map[string]interface{}{}
	path = strings.TrimSpace(path)
	if path == "" || strings.ContainsRune(path, 0) {
		result["error"] = "invalid path"
		return result
	}
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			result["error"] = "path not found"
		} else {
			result["error"] = err.Error()
		}
		return result
	}
	if info.IsDir() {
		result["error"] = "path is a directory"
		return result
	}
	if info.Size() > fileReadMaxBytes {
		result["error"] = "file too large"
		return result
	}
	data, err := os.ReadFile(path)
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	result["name"] = filepath.Base(path)
	result["path"] = path
	result["size"] = int64(len(data))
	result["data_base64"] = base64.StdEncoding.EncodeToString(data)
	return result
}
