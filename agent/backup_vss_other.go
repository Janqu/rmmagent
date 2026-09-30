//go:build !windows

package agent

import (
	"context"
	"errors"
)

func backupVSSAvailable() bool     { return false }
func BackupVSSHelper(string) error { return errors.New("VSS benötigt Windows") }
func (a *Agent) backupVSS(context.Context, []string) (*backupSnapshot, []backupReadRoot, func() error, error) {
	return nil, nil, nil, errors.New("VSS benötigt Windows; keine Sicherung aus Live-Dateien durchgeführt")
}
