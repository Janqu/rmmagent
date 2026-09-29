package agent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	backupDefaultChunk = 8 * 1024 * 1024
	backupMaxChunk     = 10 * 1024 * 1024
)

var backupCancels sync.Map

type BackupJob struct {
	RestoreID           int
	RestorePath         string
	ID                  int
	ProfileID           int
	RepoID              string
	Paths               []string
	Excludes            []string
	ChunkBytes          int
	Endpoint            string
	BlobURL             string
	ManifestURL         string
	CheckURL            string
	PreviousManifestURL string
}

type BackupSource struct {
	Path  string `json:"path"`
	Label string `json:"label"`
	Kind  string `json:"kind"`
}

type backupManifest struct {
	Format    int                  `json:"format,omitempty"`
	Parts     []string             `json:"parts,omitempty"`
	RunID     int                  `json:"run_id"`
	RepoID    string               `json:"repo_id"`
	Hostname  string               `json:"hostname"`
	StartedAt time.Time            `json:"started_at"`
	Files     []backupManifestFile `json:"files"`
}

type backupManifestFile struct {
	ChunkSizes []int     `json:"chunk_sizes,omitempty"`
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	Mode       uint32    `json:"mode"`
	ModTime    time.Time `json:"mod_time"`
	Chunks     []string  `json:"chunks"`
	VerifiedAt time.Time `json:"verified_at,omitempty"`
}

func (a *Agent) BackupSources() []BackupSource {
	var out []BackupSource
	switch runtime.GOOS {
	case "windows":
		for drive := 'A'; drive <= 'Z'; drive++ {
			path := fmt.Sprintf("%c:\\", drive)
			backupAddSource(&out, path, path, "drive")
		}
		backupAddSource(&out, `C:\Users`, "Benutzerprofile", "folder")
	case "darwin":
		backupAddSource(&out, "/Users", "Benutzer", "folder")
		backupAddSource(&out, "/Volumes", "Volumes", "drive")
	default:
		backupAddSource(&out, "/", "System", "drive")
		for _, path := range []string{"/home", "/srv", "/var", "/etc", "/mnt", "/media"} {
			backupAddSource(&out, path, path, "folder")
		}
	}
	return out
}

func (a *Agent) BackupBrowse(path string) []BackupSource {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	out := make([]BackupSource, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		child := filepath.Join(path, name)
		out = append(out, BackupSource{Path: child, Label: name, Kind: "folder"})
		if len(out) >= 500 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Label) < strings.ToLower(out[j].Label)
	})
	return out
}

func backupAddSource(out *[]BackupSource, path, label, kind string) {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return
	}
	for _, existing := range *out {
		if existing.Path == path {
			return
		}
	}
	*out = append(*out, BackupSource{Path: path, Label: label, Kind: kind})
}

func (a *Agent) RunBackup(job BackupJob) {
	ctx, cancel := context.WithCancel(context.Background())
	if job.ID != 0 {
		backupCancels.Store(job.ID, cancel)
		defer backupCancels.Delete(job.ID)
	}
	defer cancel()
	started := time.Now().UTC()
	stats, err := a.runBackup(ctx, job, started)
	if err != nil {
		state, code := "failed", 1
		if errors.Is(err, context.Canceled) {
			state, code = "canceled", 130
		}
		a.backupStatus(job.Endpoint, stats.status(job.ID, state, err.Error(), code))
		return
	}
	body := stats.status(job.ID, "success", "", 0)
	body["snapshot_id"] = fmt.Sprintf("%d", started.Unix())
	a.backupStatus(job.Endpoint, body)
}

func (a *Agent) CancelBackup(id int) bool {
	cancel, ok := backupCancels.Load(id)
	if !ok {
		return false
	}
	cancel.(context.CancelFunc)()
	return true
}

func (a *Agent) runBackup(ctx context.Context, job BackupJob, started time.Time) (backupStats, error) {
	stats := backupStats{}
	if job.ID == 0 || job.RepoID == "" || job.Endpoint == "" || job.BlobURL == "" || job.ManifestURL == "" {
		return stats, fmt.Errorf("backup job is incomplete")
	}
	chunkSize := job.ChunkBytes
	if chunkSize <= 0 {
		chunkSize = backupDefaultChunk
	}
	if chunkSize > backupMaxChunk || chunkSize < 64 {
		return stats, fmt.Errorf("invalid backup chunk size")
	}
	var previousRaw []byte
	if job.PreviousManifestURL != "" {
		resp, err := a.rClient.R().SetContext(ctx).Get(job.PreviousManifestURL)
		if err != nil {
			return stats, err
		}
		switch resp.StatusCode() {
		case 200:
			previousRaw = resp.Body()
		case 404:
		default:
			return stats, fmt.Errorf("previous manifest download failed: %s", resp.Status())
		}
	}
	key, err := a.backupRepoKey(job.RepoID, len(previousRaw) == 0)
	if err != nil {
		return stats, err
	}
	encKey, idKey := backupSubkeys(key, job.RepoID)
	transfer := &backupTransfer{agent: a, job: job, encKey: encKey, idKey: idKey, known: make(map[string]bool), stats: &stats}
	previous := make(map[string]backupManifestFile)
	if len(previousRaw) > 0 {
		manifest, err := transfer.decodeManifest(ctx, previousRaw)
		if err != nil {
			return stats, fmt.Errorf("previous manifest: %w", err)
		}
		for _, item := range manifest.Files {
			previous[item.Path] = item
		}
	}
	manifest := backupManifest{Format: 2, RunID: job.ID, RepoID: job.RepoID, Hostname: a.Hostname, StartedAt: started}
	visited := make(map[string]bool)
	var skipped int
	var lastSkipped string
	lastProgress := time.Now().UTC()
	a.backupStatus(job.Endpoint, stats.status(job.ID, "running", "", 0))
	for _, root := range job.Paths {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				if backupSkippableError(walkErr) {
					skipped++
					lastSkipped = path
					if entry != nil && entry.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				return walkErr
			}
			if backupExcluded(path, job.Excludes) {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			path, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			if visited[path] {
				return nil
			}
			visited[path] = true
			info, err := entry.Info()
			if err != nil {
				return err
			}
			item, unchanged := previous[path]
			// Metadata is the fast path, as in file-level incremental backup. Rehash
			// weekly to bound missed changes from software preserving size and mtime.
			unchanged = unchanged && item.Size == info.Size() && item.Mode == uint32(info.Mode()) && item.ModTime.Equal(info.ModTime()) && !item.VerifiedAt.IsZero() && started.Sub(item.VerifiedAt) >= 0 && started.Sub(item.VerifiedAt) < 7*24*time.Hour
			if unchanged {
				found, err := transfer.existing(ctx, item.Chunks)
				if err != nil {
					return err
				}
				for _, id := range item.Chunks {
					if !found[id] {
						unchanged = false
						break
					}
				}
			}
			if unchanged {
				stats.Total += item.Size
				stats.Reused += item.Size
				stats.ChunksReused += int64(len(item.Chunks))
				stats.Unchanged++
			} else {
				item, err = transfer.file(ctx, path, info, chunkSize, started)
				if err != nil {
					if backupSkippableError(err) {
						skipped++
						lastSkipped = path
						return nil
					}
					return err
				}
			}
			manifest.Files = append(manifest.Files, item)
			stats.Files = len(manifest.Files)
			now := time.Now().UTC()
			if backupProgressDue(now, lastProgress) {
				lastProgress = now
				body := stats.status(job.ID, "running", "", 0)
				body["log_tail"] = path
				a.backupStatus(job.Endpoint, body)
			}
			return nil
		})
		if err != nil {
			return stats, err
		}
	}
	if err := transfer.saveManifest(ctx, manifest); err != nil {
		return stats, err
	}
	if skipped > 0 {
		body := stats.status(job.ID, "running", "", 0)
		body["log_tail"] = fmt.Sprintf("%d Pfade übersprungen, zuletzt: %s", skipped, lastSkipped)
		a.backupStatus(job.Endpoint, body)
	}
	return stats, nil
}

func (b *backupTransfer) file(ctx context.Context, path string, info os.FileInfo, chunkSize int, verified time.Time) (backupManifestFile, error) {
	item := backupManifestFile{Path: path, Size: info.Size(), Mode: uint32(info.Mode()), ModTime: info.ModTime().UTC(), VerifiedAt: verified}
	file, err := os.Open(path)
	if err != nil {
		return item, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return item, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return item, fmt.Errorf("backup source changed: %s", path)
	}
	var chunks [][]byte
	var ids []string
	buffered := 0
	var read int64
	flush := func() error {
		found, err := b.existing(ctx, ids)
		if err != nil {
			return err
		}
		for i, id := range ids {
			if found[id] || b.known[id] {
				b.stats.Reused += int64(len(chunks[i]))
				b.stats.ChunksReused++
			} else {
				if err := b.put(ctx, id, chunks[i]); err != nil {
					return err
				}
				b.stats.ChunksUploaded++
			}
			b.stats.Total += int64(len(chunks[i]))
		}
		chunks = nil
		ids = nil
		buffered = 0
		return nil
	}
	err = backupChunks(ctx, file, chunkSize, func(chunk []byte) error {
		id := backupBlobID(b.idKey, chunk)
		item.Chunks = append(item.Chunks, id)
		item.ChunkSizes = append(item.ChunkSizes, len(chunk))
		chunks = append(chunks, bytes.Clone(chunk))
		ids = append(ids, id)
		buffered += len(chunk)
		read += int64(len(chunk))
		if buffered >= 4<<20 || len(ids) >= 128 {
			return flush()
		}
		return nil
	})
	if err != nil {
		return item, err
	}
	if len(ids) > 0 {
		if err := flush(); err != nil {
			return item, err
		}
	}
	after, err := file.Stat()
	if err != nil {
		return item, err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return item, err
	}
	if read != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) || !os.SameFile(after, current) || !current.ModTime().Equal(info.ModTime()) {
		return item, fmt.Errorf("file changed during backup: %s", path)
	}
	return item, nil
}

func (a *Agent) RunBackupRestore(job BackupJob) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if job.RestoreID != 0 {
		backupRestoreCancels.Store(job.RestoreID, cancel)
		defer backupRestoreCancels.Delete(job.RestoreID)
	}
	path, files, size, err := a.restoreSnapshot(ctx, job)
	state, message := "success", ""
	if err != nil {
		state, message = "failed", err.Error()
		if errors.Is(err, context.Canceled) {
			state = "canceled"
		}
		a.Logger.Errorln("backup restore:", err)
	}
	if err := a.backupRestoreReport(job, state, path, files, size, message); err != nil {
		a.Logger.Errorln("restore status:", err)
	}
}

func (a *Agent) runBackupRestore(job BackupJob) error {
	_, _, _, err := a.restoreSnapshot(context.Background(), job)
	return err
}

func (b *backupTransfer) restoreFile(ctx context.Context, root string, item backupManifestFile) (result error) {
	target, err := backupRestorePath(root, item.Path)
	if err != nil {
		return err
	}
	if item.Size < 0 {
		return fmt.Errorf("invalid restored file size")
	}
	dir, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return err
	}
	if err := dir.MkdirAll(filepath.Dir(relative), 0700); err != nil {
		return err
	}
	out, err := dir.OpenFile(relative, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		out.Close()
		if result != nil {
			_ = dir.Remove(relative)
		}
	}()
	var size int64
	for _, id := range item.Chunks {
		chunk, err := b.get(ctx, id)
		if err != nil {
			return err
		}
		size += int64(len(chunk))
		if size > item.Size {
			return fmt.Errorf("restored file exceeds expected size")
		}
		if _, err := out.Write(chunk); err != nil {
			return err
		}
	}
	if size != item.Size {
		return fmt.Errorf("restored file size mismatch")
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if mode := os.FileMode(item.Mode).Perm(); mode != 0 {
		if err := dir.Chmod(relative, mode); err != nil {
			return err
		}
	}
	return dir.Chtimes(relative, item.ModTime, item.ModTime)
}

var backupRepoPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (a *Agent) backupRepoKey(repoID string, create bool) ([]byte, error) {
	if !backupRepoPattern.MatchString(repoID) {
		return nil, fmt.Errorf("invalid backup repository ID")
	}
	dir := filepath.Join(a.ProgramDir, "backup")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, repoID+".key")
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, fmt.Errorf("invalid existing backup key; refusing to replace it")
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if !create {
		return nil, fmt.Errorf("backup encryption key is missing; restore the original key")
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if os.IsExist(err) {
		return a.backupRepoKey(repoID, false)
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if _, err := file.Write(key); err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return key, nil
}

func backupSubkeys(master []byte, repoID string) ([]byte, []byte) {
	reader := hkdf.New(sha256.New, master, []byte(repoID), []byte("qdt-backup-v1"))
	out := make([]byte, 64)
	_, _ = io.ReadFull(reader, out)
	return out[:32], out[32:]
}

func backupBlobID(key, chunk []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(chunk)
	return hex.EncodeToString(mac.Sum(nil))
}

func backupSeal(key, aad, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

func backupOpen(key, aad, sealed []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := sealed[:chacha20poly1305.NonceSizeX]
	return aead.Open(nil, nonce, sealed[chacha20poly1305.NonceSizeX:], aad)
}

func (a *Agent) backupStatus(endpoint string, body map[string]interface{}) {
	if endpoint == "" {
		return
	}
	_, _ = a.rClient.R().SetBody(body).Post(endpoint)
}

func backupProgressDue(now, last time.Time) bool {
	return now.Sub(last) >= 5*time.Second
}

func backupSkippableError(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist)
}

func backupExcluded(path string, patterns []string) bool {
	base := filepath.Base(path)
	clean := filepath.ToSlash(path)
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if ok, _ := filepath.Match(pattern, base); ok {
			return true
		}
		if ok, _ := filepath.Match(pattern, clean); ok {
			return true
		}
		if strings.Contains(clean, filepath.ToSlash(pattern)) {
			return true
		}
	}
	return false
}

func backupRestorePath(root, original string) (string, error) {
	clean := filepath.ToSlash(filepath.Clean(original))
	clean = strings.TrimPrefix(clean, filepath.VolumeName(clean))
	clean = strings.TrimLeft(clean, "/")
	if clean == "." || clean == "" || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", fmt.Errorf("unsafe restore path")
	}
	clean = strings.ReplaceAll(clean, ":", "_")
	return filepath.Join(root, filepath.FromSlash(clean)), nil
}

func backupOpenForTest(key, aad, sealed []byte) ([]byte, error) {
	return backupOpen(key, aad, bytes.Clone(sealed))
}
