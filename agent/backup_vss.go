package agent

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

type backupSnapshotVolume struct {
	Volume string `json:"volume"`
	ID     string `json:"id"`
	Device string `json:"device,omitempty"`
}
type backupSnapshot struct {
	Mode      string                 `json:"mode"`
	Status    string                 `json:"status"`
	CreatedAt time.Time              `json:"created_at"`
	Volumes   []backupSnapshotVolume `json:"volumes"`
}
type backupReadRoot struct{ Original, Read string }

func backupOriginalPath(root backupReadRoot, path string) (string, error) {
	relative, err := filepath.Rel(root.Read, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", errors.New("snapshot path escapes its source")
	}
	return filepath.Join(root.Original, relative), nil
}

func (a *Agent) runBackup(ctx context.Context, job BackupJob, started time.Time) (stats backupStats, result error) {
	if err := ctx.Err(); err != nil {
		return stats, err
	}
	if job.VSSMode == "" || job.VSSMode == "off" {
		return a.runBackupData(ctx, job, started)
	}
	if job.VSSMode != "required" {
		return stats, errors.New("Unbekannter VSS-Modus; Sicherung abgelehnt.")
	}
	report := func(snapshot *backupSnapshot) {
		body := stats.status(job.ID, "running", "", 0)
		body["vss_result"] = snapshot
		a.backupStatus(job.Endpoint, body)
	}
	report(&backupSnapshot{Mode: "required", Status: "preparing", Volumes: []backupSnapshotVolume{}})
	snapshot, roots, cleanup, err := a.backupVSS(ctx, job.Paths)
	if err != nil {
		report(&backupSnapshot{Mode: "required", Status: "failed", Volumes: []backupSnapshotVolume{}})
		return stats, fmt.Errorf("VSS: %w", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			result = errors.Join(result, fmt.Errorf("VSS-Aufräumen: %w", err))
		}
		snapshot.Status = "released"
		if result != nil {
			snapshot.Status = "failed"
		}
		report(snapshot)
	}()
	snapshot.Status = "reading"
	report(snapshot)
	job.snapshot, job.readRoots = snapshot, roots
	return a.runBackupData(ctx, job, started)
}
