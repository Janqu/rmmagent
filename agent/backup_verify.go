package agent

import (
	"context"
	"fmt"
	"time"
)

// Read every referenced block through the authenticated decrypt/hash path.
// No plaintext archive, restore directory or local block cache is written.
func (a *Agent) verifyBackupSnapshot(ctx context.Context, job BackupJob) (int64, int64, error) {
	transfer, manifest, err := a.backupSnapshot(ctx, job)
	if err != nil {
		return 0, 0, err
	}
	var files, total int64
	lastReport := time.Now()
	report := func(force bool) error {
		if !force && time.Since(lastReport) < 5*time.Second {
			return nil
		}
		lastReport = time.Now()
		return a.backupRestoreReport(job, "running", "", files, total, "")
	}
	if err := report(true); err != nil {
		return files, total, err
	}
	for _, item := range manifest.Files {
		if err := ctx.Err(); err != nil {
			return files, total, err
		}
		if item.Size < 0 || (len(item.ChunkSizes) > 0 && len(item.ChunkSizes) != len(item.Chunks)) {
			return files, total, fmt.Errorf("invalid file metadata: %s", item.Path)
		}
		var size int64
		for i, id := range item.Chunks {
			chunk, err := transfer.get(ctx, id)
			if err != nil {
				return files, total, fmt.Errorf("verify %s: %w", item.Path, err)
			}
			n := int64(len(chunk))
			if n > item.Size-size || (len(item.ChunkSizes) > 0 && len(chunk) != item.ChunkSizes[i]) {
				return files, total, fmt.Errorf("chunk size mismatch: %s", item.Path)
			}
			size += n
			total += n
			if err := report(false); err != nil {
				return files, total, err
			}
		}
		if size != item.Size {
			return files, total, fmt.Errorf("file size mismatch: %s", item.Path)
		}
		files++
	}
	return files, total, nil
}
