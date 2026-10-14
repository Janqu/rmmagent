package agent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// One agent process owns its key directory. Serialize creation, import and
// legacy-format migration so none can replace a concurrently selected key.
var backupKeyMu sync.Mutex

func (a *Agent) backupStoredKey(repo string, create bool, imported []byte) ([]byte, error) {
	if !backupRepoPattern.MatchString(repo) {
		return nil, fmt.Errorf("invalid backup repository ID")
	}
	backupKeyMu.Lock()
	defer backupKeyMu.Unlock()
	dir := filepath.Join(a.ProgramDir, "backup")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := backupRestrictKeyPath(dir, true); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, repo+".key")
	info, err := os.Lstat(path)
	if err == nil && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("backup key must be a regular file")
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	stored, err := os.ReadFile(path)
	if err == nil {
		if err := backupRestrictKeyPath(path, false); err != nil {
			return nil, err
		}
		key, err := backupUnprotectLocalKey(stored)
		if err != nil {
			return nil, err
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("invalid existing backup key; refusing to replace it")
		}
		if imported != nil && !bytes.Equal(imported, key) {
			return nil, fmt.Errorf("refusing to overwrite a different existing key")
		}
		if len(stored) == 32 {
			protected, err := backupProtectLocalKey(key)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(stored, protected) {
				if err := backupWriteLocalKey(path, protected); err != nil {
					return nil, err
				}
			}
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if !create && imported == nil {
		return nil, fmt.Errorf("backup encryption key is missing; restore the original key")
	}
	key := imported
	if key == nil {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length")
	}
	protected, err := backupProtectLocalKey(key)
	if err != nil {
		return nil, err
	}
	if err := backupWriteLocalKey(path, protected); err != nil {
		return nil, err
	}
	return bytes.Clone(key), nil
}

func backupWriteLocalKey(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".backup-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = backupRestrictKeyPath(f.Name(), false); err != nil {
		f.Close()
		return err
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
