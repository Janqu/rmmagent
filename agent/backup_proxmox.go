package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const backupProxmoxConfig = "/etc/pve/local"

var backupProxmoxSource = regexp.MustCompile(`^proxmox://(qemu|lxc)/([1-9][0-9]{2,8})$`)

func backupProxmoxAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("vzdump")
	info, statErr := os.Stat(backupProxmoxConfig)
	return err == nil && statErr == nil && info.IsDir()
}

func backupProxmoxSources(configDir string) []BackupSource {
	var sources []BackupSource
	for _, kind := range []string{"qemu", "lxc"} {
		dir := kind
		if kind == "qemu" {
			dir = "qemu-server"
		}
		entries, _ := os.ReadDir(filepath.Join(configDir, dir))
		for _, entry := range entries {
			id := strings.TrimSuffix(entry.Name(), ".conf")
			source := "proxmox://" + kind + "/" + id
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") || !backupProxmoxSource.MatchString(source) {
				continue
			}
			label := "Proxmox VM " + id
			if kind == "lxc" {
				label = "Proxmox LXC " + id
			}
			if data, err := os.ReadFile(filepath.Join(configDir, dir, entry.Name())); err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					if strings.HasPrefix(line, "[") { // Only current config, not saved snapshots.
						break
					}
					key, name, ok := strings.Cut(line, ":")
					if ok && (key == "name" || key == "hostname") {
						label += " – " + strings.TrimSpace(name)
						break
					}
				}
			}
			sources = append(sources, BackupSource{Path: source, Label: label, Kind: "proxmox_" + kind})
		}
	}
	return sources
}

func backupProxmoxArchive(ctx context.Context, source, configDir, stagingDir, tool string, progress func()) (root backupReadRoot, cleanup func() error, result error) {
	cleanup = func() error { return nil }
	match := backupProxmoxSource.FindStringSubmatch(source)
	if match == nil {
		return root, cleanup, errors.New("Ungültige Proxmox-Quelle; erwartet proxmox://qemu/100 oder proxmox://lxc/100")
	}
	kind, id := match[1], match[2]
	dir, suffix := "lxc", ".tar.zst"
	if kind == "qemu" {
		dir, suffix = "qemu-server", ".vma.zst"
	}
	if info, err := os.Stat(filepath.Join(configDir, dir, id+".conf")); err != nil || !info.Mode().IsRegular() {
		return root, cleanup, fmt.Errorf("Proxmox-Gast %s/%s ist auf diesem Host nicht vorhanden", kind, id)
	}
	if err := os.MkdirAll(stagingDir, 0700); err != nil {
		return root, cleanup, err
	}
	// ponytail: stage one full guest archive at a time; stream if local space becomes a constraint.
	temp, err := os.MkdirTemp(stagingDir, "vzdump-")
	if err != nil {
		return root, cleanup, err
	}
	cleanup = func() error { return os.RemoveAll(temp) }
	defer func() {
		if result != nil {
			result = errors.Join(result, cleanup())
		}
	}()
	cmd := exec.CommandContext(ctx, tool, id, "--mode", "snapshot", "--compress", "zstd", "--dumpdir", temp, "--remove", "0", "--quiet", "1")
	// Allow vzdump to release snapshots/guest locks on cancellation before forcing exit.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 2 * time.Minute
	log := newCappedBuffer(8192)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		return root, cleanup, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			if ctx.Err() != nil {
				return root, cleanup, ctx.Err()
			}
			if err != nil {
				return root, cleanup, fmt.Errorf("vzdump %s/%s: %w: %s", kind, id, err, strings.TrimSpace(log.String()))
			}
			entries, err := os.ReadDir(temp)
			if err != nil {
				return root, cleanup, err
			}
			for _, entry := range entries {
				if !strings.HasPrefix(entry.Name(), "vzdump-"+kind+"-"+id+"-") || !strings.HasSuffix(entry.Name(), suffix) {
					continue
				}
				info, err := entry.Info()
				if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || root.Read != "" {
					return backupReadRoot{}, cleanup, errors.New("vzdump lieferte kein eindeutiges, vollständiges Archiv")
				}
				root = backupReadRoot{Original: filepath.Join("/proxmox", kind, id, entry.Name()), Read: filepath.Join(temp, entry.Name())}
			}
			if root.Read == "" {
				return root, cleanup, errors.New("vzdump hat kein Backup-Archiv erstellt")
			}
			return root, cleanup, nil
		case <-ticker.C:
			if progress != nil {
				progress()
			}
		}
	}
}
