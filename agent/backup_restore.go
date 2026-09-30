package agent

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var backupRestoreCancels sync.Map

func (a *Agent) backupSnapshot(ctx context.Context, job BackupJob) (*backupTransfer, backupManifest, error) {
	var manifest backupManifest
	key, err := a.backupRepoKey(job.RepoID, false)
	if err != nil {
		return nil, manifest, err
	}
	encKey, idKey := backupSubkeys(key, job.RepoID)
	transfer := &backupTransfer{agent: a, job: job, encKey: encKey, idKey: idKey}
	resp, err := a.rClient.R().SetContext(ctx).Get(job.ManifestURL)
	if err != nil {
		return nil, manifest, err
	}
	if resp.StatusCode() != 200 {
		return nil, manifest, fmt.Errorf("manifest download failed: %s", resp.Status())
	}
	manifest, err = transfer.decodeManifest(ctx, resp.Body())
	if err != nil {
		return nil, manifest, err
	}
	if manifest.RunID != job.ID {
		return nil, manifest, fmt.Errorf("backup manifest run mismatch")
	}
	return transfer, manifest, nil
}

func backupSelected(path string, selected []string) bool {
	if len(selected) == 0 {
		return true
	}
	// Compare recorded paths, independent of the current agent's path separator.
	normalized := strings.ReplaceAll(path, "\\", "/")
	for _, entry := range selected {
		entry = strings.TrimRight(strings.ReplaceAll(entry, "\\", "/"), "/")
		if normalized == entry || strings.HasPrefix(normalized, entry+"/") {
			return true
		}
	}
	return false
}

func (a *Agent) backupInspect(job BackupJob, data map[string]string) map[string]interface{} {
	failure := func(err error) map[string]interface{} { return map[string]interface{}{"error": err.Error()} }
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	transfer, manifest, err := a.backupSnapshot(ctx, job)
	if err != nil {
		return failure(err)
	}
	if data["operation"] == "content" {
		offset, err := strconv.ParseInt(data["offset"], 10, 64)
		if err != nil || offset < 0 {
			return failure(fmt.Errorf("invalid file offset"))
		}
		for _, item := range manifest.Files {
			if item.Path != data["path"] {
				continue
			}
			content, err := transfer.fileRange(ctx, item, offset, 512<<10)
			if err != nil {
				return failure(err)
			}
			mime := "application/octet-stream"
			if offset == 0 {
				mime = http.DetectContentType(content)
			}
			return map[string]interface{}{"data": base64.StdEncoding.EncodeToString(content), "size": item.Size, "offset": offset, "eof": offset+int64(len(content)) >= item.Size, "mime": mime}
		}
		return failure(fmt.Errorf("file is not present in this snapshot"))
	}
	return backupBrowseManifest(manifest, data)
}

func backupBrowseManifest(manifest backupManifest, data map[string]string) map[string]interface{} {
	offset, err := strconv.Atoi(data["offset"])
	if err != nil || offset < 0 {
		return map[string]interface{}{"error": "invalid page offset"}
	}
	query := strings.ToLower(data["query"])
	tree := data["view"] == "tree" && query == ""
	folder := strings.TrimRight(strings.ReplaceAll(data["folder"], "\\", "/"), "/")
	dirs := map[string]bool{}
	var matches []map[string]interface{}
	for _, item := range manifest.Files {
		normalized := strings.ReplaceAll(item.Path, "\\", "/")
		if !strings.Contains(strings.ToLower(item.Path), query) {
			continue
		}
		if folder != "" && !backupSelected(item.Path, []string{folder}) {
			continue
		}
		if tree {
			relative := strings.TrimLeft(strings.TrimPrefix(normalized, folder), "/")
			if slash := strings.IndexByte(relative, '/'); slash >= 0 {
				dir := relative[:slash]
				full := dir
				if folder != "" {
					full = folder + "/" + dir
				} else if strings.HasPrefix(normalized, "//") {
					full = "//" + dir
				} else if strings.HasPrefix(normalized, "/") {
					full = "/" + dir
				}
				dirs[full] = true
				continue
			}
		}
		matches = append(matches, map[string]interface{}{"path": item.Path, "size": item.Size, "modified": item.ModTime.Format(time.RFC3339), "kind": "file"})
	}
	for dir := range dirs {
		matches = append(matches, map[string]interface{}{"path": dir, "size": 0, "kind": "directory"})
	}
	sort.Slice(matches, func(i, j int) bool {
		a, b := matches[i], matches[j]
		if a["kind"] != b["kind"] {
			return a["kind"] == "directory"
		}
		return a["path"].(string) < b["path"].(string)
	})
	var entries []map[string]interface{}
	replyBytes := 0
	for index := offset; index < len(matches) && len(entries) < 100; index++ {
		item := matches[index]
		size := len(item["path"].(string)) + 128
		if replyBytes+size > 512<<10 {
			break
		}
		entries = append(entries, item)
		replyBytes += size
	}
	parent := ""
	if folder != "" {
		parent = path.Dir(folder)
		if parent == "." || parent == "/" {
			parent = ""
		}
	}
	return map[string]interface{}{"files": entries, "total": len(matches), "offset": offset, "parent": parent, "tree": tree}
}

func (b *backupTransfer) fileRange(ctx context.Context, item backupManifestFile, offset int64, limit int) ([]byte, error) {
	if item.Size < 0 || offset > item.Size {
		return nil, fmt.Errorf("invalid file size or offset")
	}
	indexed := len(item.ChunkSizes) > 0
	if indexed {
		if len(item.ChunkSizes) != len(item.Chunks) {
			return nil, fmt.Errorf("invalid chunk index")
		}
		var sum int64
		for _, size := range item.ChunkSizes {
			if size <= 0 || size > backupMaxChunk {
				return nil, fmt.Errorf("invalid indexed chunk size")
			}
			sum += int64(size)
			if sum > item.Size {
				return nil, fmt.Errorf("invalid chunk index size")
			}
		}
		if sum != item.Size {
			return nil, fmt.Errorf("incomplete chunk index")
		}
	}
	out := make([]byte, 0, limit)
	var position int64
	for index, id := range item.Chunks {
		if indexed && position+int64(item.ChunkSizes[index]) <= offset {
			position += int64(item.ChunkSizes[index])
			continue
		}
		chunk, err := b.get(ctx, id)
		if err != nil {
			return nil, err
		}
		if indexed && len(chunk) != item.ChunkSizes[index] {
			return nil, fmt.Errorf("chunk index integrity mismatch")
		}
		next := position + int64(len(chunk))
		if next > item.Size {
			return nil, fmt.Errorf("invalid file chunk sizes")
		}
		if next > offset {
			start := int64(0)
			if offset > position {
				start = offset - position
			}
			chunk = chunk[start:]
			if len(chunk) > limit-len(out) {
				chunk = chunk[:limit-len(out)]
			}
			out = append(out, chunk...)
		}
		position = next
		if len(out) == limit {
			return out, nil
		}
	}
	if position != item.Size {
		return nil, fmt.Errorf("incomplete file chunks")
	}
	return out, nil
}

func (a *Agent) backupRestoreReport(job BackupJob, state, path string, files, bytes int64, message string) error {
	if job.RestoreID == 0 {
		return nil
	}
	response, err := a.rClient.R().SetBody(map[string]interface{}{"status": state, "destination": path, "files": files, "bytes_restored": bytes, "error": message}).Post(job.Endpoint)
	if err != nil {
		return err
	}
	if response.StatusCode() != 200 {
		return fmt.Errorf("restore status: %s", response.Status())
	}
	return nil
}

func (a *Agent) restoreSnapshot(ctx context.Context, job BackupJob) (string, int64, int64, error) {
	if job.ID == 0 || job.RepoID == "" || job.BlobURL == "" || job.ManifestURL == "" {
		return "", 0, 0, fmt.Errorf("backup restore job is incomplete")
	}
	transfer, manifest, err := a.backupSnapshot(ctx, job)
	if err != nil {
		return "", 0, 0, err
	}
	parent := job.RestorePath
	if parent == "" {
		var resolveErr error
		parent, resolveErr = filepath.Abs(filepath.Join(a.ProgramDir, "restore"))
		if resolveErr != nil {
			return "", 0, 0, resolveErr
		}
		if err := os.MkdirAll(parent, 0700); err != nil {
			return "", 0, 0, err
		}
	}
	if !filepath.IsAbs(parent) {
		return "", 0, 0, fmt.Errorf("restore destination must be absolute")
	}
	// Always create a new directory; a retry never overwrites existing data.
	root, err := os.MkdirTemp(parent, fmt.Sprintf("backup-%d-", job.ID))
	if err != nil {
		return "", 0, 0, err
	}
	var files, restored int64
	if err := a.backupRestoreReport(job, "running", root, 0, 0, ""); err != nil {
		return root, 0, 0, err
	}
	lastReport := time.Now()
	for _, item := range manifest.Files {
		if !backupSelected(item.Path, job.Paths) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return root, files, restored, err
		}
		if err := transfer.restoreFile(ctx, root, item); err != nil {
			return root, files, restored, err
		}
		files++
		restored += item.Size
		if time.Since(lastReport) > 5*time.Second {
			if err := a.backupRestoreReport(job, "running", root, files, restored, ""); err != nil {
				return root, files, restored, err
			}
			lastReport = time.Now()
		}
	}
	if len(job.Paths) > 0 && files == 0 {
		return root, 0, 0, fmt.Errorf("no files matched the restore selection")
	}
	return root, files, restored, nil
}
