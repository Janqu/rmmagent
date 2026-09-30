package agent

import (
	"fmt"
	"github.com/shirou/gopsutil/v3/disk"
	"os"
	"path/filepath"
	"time"
)

func backupDestinationCheck(path string) map[string]interface{} {
	failure := func(err error) map[string]interface{} { return map[string]interface{}{"error": err.Error()} }
	if !filepath.IsAbs(path) {
		return failure(fmt.Errorf("storage path must be absolute"))
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return failure(err)
	}
	defer root.Close()
	name := fmt.Sprintf(".qdt-write-check-%d", time.Now().UnixNano())
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return failure(err)
	}
	defer root.Remove(name)
	_, writeErr := f.Write([]byte("QDT storage write check\n"))
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil {
		return failure(writeErr)
	}
	if syncErr != nil {
		return failure(syncErr)
	}
	if closeErr != nil {
		return failure(closeErr)
	}
	result := map[string]interface{}{"ok": true, "path": path}
	if usage, err := disk.Usage(path); err == nil {
		result["free_bytes"] = usage.Free
		result["total_bytes"] = usage.Total
	}
	return result
}
