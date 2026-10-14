//go:build !windows

package agent

import "os"

// Unix has no universal unattended secret store. Use service-only permissions;
// this is access control, not encryption at rest or protection against root.
func backupProtectLocalKey(key []byte) ([]byte, error)   { return key, nil }
func backupUnprotectLocalKey(key []byte) ([]byte, error) { return key, nil }
func backupRestrictKeyPath(path string, dir bool) error {
	mode := os.FileMode(0600)
	if dir {
		mode = 0700
	}
	return os.Chmod(path, mode)
}
