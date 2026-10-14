package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var backupNativeSource = regexp.MustCompile(`^(database://(postgresql|mariadb|mysql|mssql)|image://windows)/([A-Za-z0-9][A-Za-z0-9_-]{0,63})$`)
var backupZFSSource = regexp.MustCompile(`^zfs://[A-Za-z][A-Za-z0-9_.:-]*(/[A-Za-z0-9_][A-Za-z0-9_.:-]*)*$`)
var backupImageLock sync.Mutex
var backupPGService = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
var backupSQLServer = regexp.MustCompile(`(?i)^(\.|\(local\)|localhost)(\\[A-Za-z0-9_-]+)?$`)

// Credentials and staging locations are local agent configuration, never job payloads.
type backupNativeConfig struct {
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	Label          string `json:"label,omitempty"`
	Tool           string `json:"tool,omitempty"`
	ServiceFile    string `json:"service_file,omitempty"`
	Service        string `json:"service,omitempty"`
	DefaultsFile   string `json:"defaults_file,omitempty"`
	Database       string `json:"database,omitempty"`
	Server         string `json:"server,omitempty"`
	Username       string `json:"username,omitempty"`
	PasswordFile   string `json:"password_file,omitempty"`
	StagingDir     string `json:"staging_dir,omitempty"`
}

func backupExportSource(path string) bool {
	return strings.HasPrefix(path, "proxmox:") || strings.HasPrefix(path, "zfs:") || strings.HasPrefix(path, "database:") || strings.HasPrefix(path, "image:")
}

func backupPrivateFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("Backup-Konfigurationsdatei benötigt einen absoluten Pfad")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1024*1024 || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("Backup-Konfigurationsdatei fehlt oder ist nicht geschützt (Unix: Modus 0600, keine Symlinks)")
	}
	return os.ReadFile(path)
}

// backupTrustedDir rejects a directory that accounts other than its owner can
// write to. Only meaningful for files whose contents steer a root process.
func backupTrustedDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if mode := info.Mode().Perm(); mode&0022 != 0 {
		return fmt.Errorf("%s ist für andere Konten beschreibbar (Modus %#o); chmod 0700 setzen", dir, mode)
	}
	return nil
}

func (a *Agent) backupNativeConfigs() (map[string]backupNativeConfig, error) {
	dir := filepath.Join(a.ProgramDir, "backup")
	path := filepath.Join(dir, "native-sources.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	// native-sources.json names the binary we exec as root (backupNativeTool)
	// and its staging directory. A 0600 file in a directory someone else can
	// write to can simply be replaced, so the directory decides trust too.
	_ = backupRestrictKeyPath(dir, true)
	if err := backupTrustedDir(dir); err != nil {
		return nil, fmt.Errorf("native-sources.json liegt in einem unsicheren Verzeichnis: %w", err)
	}
	data, err := backupPrivateFile(path)
	if err != nil {
		return nil, err
	}
	var configs map[string]backupNativeConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&configs); err != nil || configs == nil {
		return nil, errors.New("native-sources.json ist ungültig: Quellen-Objekt und Feldnamen prüfen")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("native-sources.json enthält zusätzliche Daten nach dem Quellen-Objekt")
	}
	return configs, nil
}

// Shared by discovery and execution, so a displayed problem also prevents exports.
func backupNativeValidate(source string, c backupNativeConfig) error {
	if !backupNativeSource.MatchString(source) && !backupZFSSource.MatchString(source) {
		return errors.New("Ungültige native Backup-Quelle")
	}
	if c.TimeoutSeconds < 0 || c.TimeoutSeconds > 86400 || (c.TimeoutSeconds != 0 && !strings.HasPrefix(source, "database:")) {
		return errors.New("timeout_seconds gilt nur für Datenbanken: 1–86400 Sekunden, 0 verwendet den Standard von 3600 Sekunden")
	}
	if c.Tool != "" && !filepath.IsAbs(c.Tool) {
		return errors.New("Konfigurierter Werkzeugpfad muss absolut sein")
	}
	if c.StagingDir != "" && !filepath.IsAbs(c.StagingDir) {
		return errors.New("Staging-Verzeichnis muss absolut sein")
	}
	switch {
	case strings.HasPrefix(source, "database://postgresql/"):
		if !backupPGService.MatchString(c.Service) {
			return errors.New("PostgreSQL: service fehlt oder ist ungültig")
		}
		if _, err := backupPrivateFile(c.ServiceFile); err != nil {
			return fmt.Errorf("PostgreSQL service_file: %w", err)
		}
	case strings.HasPrefix(source, "database://mariadb/"), strings.HasPrefix(source, "database://mysql/"):
		if c.Database == "" || strings.HasPrefix(c.Database, "-") || strings.ContainsAny(c.Database, "\x00\r\n") {
			return errors.New("Datenbankname fehlt oder ist ungültig")
		}
		if _, err := backupPrivateFile(c.DefaultsFile); err != nil {
			return fmt.Errorf("Datenbank defaults_file: %w", err)
		}
	case strings.HasPrefix(source, "database://mssql/"):
		if c.Database == "" || strings.ContainsAny(c.Database, "\x00\r\n") || c.StagingDir == "" {
			return errors.New("MSSQL benötigt database und ein für den SQL-Dienst beschreibbares staging_dir")
		}
		if !backupSQLServer.MatchString(c.Server) {
			return errors.New("MSSQL server muss ., (local) oder localhost sein, optional mit \\INSTANZ")
		}
		if c.Username != "" {
			password, err := backupPrivateFile(c.PasswordFile)
			if err != nil {
				return fmt.Errorf("MSSQL password_file: %w", err)
			}
			if len(bytes.TrimRight(password, "\r\n")) == 0 {
				return errors.New("MSSQL password_file ist leer")
			}
		}
	case strings.HasPrefix(source, "image:"):
		if runtime.GOOS != "windows" {
			return errors.New("Systemimage benötigt einen Windows-Agenten mit wbadmin")
		}
		parts := strings.Split(strings.TrimPrefix(c.StagingDir, `\\`), `\`)
		if !strings.HasPrefix(c.StagingDir, `\\`) || len(parts) < 2 {
			return errors.New("Windows-Systemimage benötigt ein UNC-staging_dir, z. B. \\\\server\\freigabe\\pc01")
		}
		for _, part := range parts {
			if part == "" || part == "." || part == ".." || strings.ContainsAny(part, `/:*?"<>|`) {
				return errors.New("Windows UNC-staging_dir ist ungültig; Server und Freigabe prüfen")
			}
		}
	}
	if _, err := exec.LookPath(backupNativeTool(source, c)); err != nil {
		return errors.New("Backup-Werkzeug fehlt im Dienst-PATH; installieren oder absoluten tool-Pfad konfigurieren")
	}
	return nil
}

func backupNativeTool(source string, c backupNativeConfig) string {
	if c.Tool != "" {
		return c.Tool
	}
	switch {
	case strings.HasPrefix(source, "database://postgresql/"):
		return "pg_dump"
	case strings.HasPrefix(source, "database://mariadb/"):
		return "mariadb-dump"
	case strings.HasPrefix(source, "database://mysql/"):
		return "mysqldump"
	case strings.HasPrefix(source, "database://mssql/"):
		return "sqlcmd"
	case strings.HasPrefix(source, "image://windows/"):
		return "wbadmin"
	}
	return "zfs"
}

func (a *Agent) backupNativeSources() []BackupSource {
	var out []BackupSource
	configs, err := a.backupNativeConfigs()
	if err != nil {
		out = append(out, BackupSource{Kind: "notice", Label: "Native Backup-Konfiguration", Problem: err.Error()})
	}
	for source, c := range configs {
		if !backupNativeSource.MatchString(source) {
			out = append(out, BackupSource{Kind: "notice", Label: "Native Backup-Konfiguration", Problem: "Ein Quellenschlüssel in native-sources.json ist ungültig; URI-Schema und Alias prüfen"})
			continue
		}
		kind, name, _ := strings.Cut(source, "://")
		if strings.TrimSpace(c.Label) != "" {
			name = c.Label
		}
		entry := BackupSource{Path: source, Label: name, Kind: kind}
		if err := backupNativeValidate(source, c); err != nil {
			entry.Problem = err.Error()
		}
		out = append(out, entry)
	}
	if _, err := exec.LookPath("zfs"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		buf := newCappedBuffer(1024 * 1024)
		cmd := exec.CommandContext(ctx, "zfs", "list", "-H", "-o", "name", "-t", "filesystem,volume")
		cmd.Stdout = buf
		if cmd.Run() == nil {
			for _, name := range strings.Fields(buf.String()) {
				if backupZFSSource.MatchString("zfs://" + name) {
					out = append(out, BackupSource{Path: "zfs://" + name, Label: "ZFS " + name, Kind: "zfs"})
				}
			}
		} else {
			out = append(out, BackupSource{Kind: "notice", Label: "ZFS-Quellen", Problem: "ZFS-Datasets konnten nicht gelesen werden; Dienstrechte und Pool-Status prüfen"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Do not return native tool output: connection errors can contain credentials.
func backupNativeRun(ctx context.Context, cmd *exec.Cmd, progress func()) error {
	// Reuse the agent's child-process cleanup; CommandContext still drives cancellation.
	if cmd.Cancel != nil {
		cmd.Cancel = func() error {
			if err := KillProc(int32(cmd.Process.Pid)); err != nil {
				return cmd.Process.Kill()
			}
			return nil
		}
	}
	cmd.WaitDelay = 5 * time.Second
	cmd.Stderr = io.Discard
	if cmd.Stdout == nil {
		cmd.Stdout = io.Discard
	}
	if err := cmd.Start(); err != nil {
		return errors.New("Backup-Werkzeug konnte nicht gestartet werden; Installation und Dienstrechte prüfen")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			if ctx.Err() != nil {
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return fmt.Errorf("Zeitlimit für nativen Backup-Export überschritten: %w", ctx.Err())
				}
				return ctx.Err()
			}
			if err != nil {
				return fmt.Errorf("Nativer Backup-Export fehlgeschlagen (%w); Verbindung, Rechte und freien Speicher prüfen", err)
			}
			return nil
		case <-ticker.C:
			if progress != nil {
				progress()
			}
		}
	}
}

func (a *Agent) backupNativeArchive(ctx context.Context, source string, progress func()) (root backupReadRoot, cleanup func() error, result error) {
	cleanup = func() error { return nil }
	if err := ctx.Err(); err != nil {
		return root, cleanup, err
	}
	if !backupNativeSource.MatchString(source) && !backupZFSSource.MatchString(source) {
		return root, cleanup, errors.New("Ungültige native Backup-Quelle")
	}
	c := backupNativeConfig{}
	if !strings.HasPrefix(source, "zfs:") {
		configs, err := a.backupNativeConfigs()
		if err != nil {
			return root, cleanup, err
		}
		var ok bool
		c, ok = configs[source]
		if !ok {
			return root, cleanup, errors.New("Quelle ist nicht in native-sources.json auf dem Agenten eingerichtet")
		}
	}
	if err := backupNativeValidate(source, c); err != nil {
		return root, cleanup, err
	}
	if strings.HasPrefix(source, "database:") {
		timeout := c.TimeoutSeconds
		if timeout == 0 {
			timeout = 3600
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()
	}
	isImage := strings.HasPrefix(source, "image:")
	if isImage {
		if !backupImageLock.TryLock() {
			return root, cleanup, errors.New("Auf diesem Agenten läuft bereits eine Image-Sicherung")
		}
		defer backupImageLock.Unlock()
	}
	staging := c.StagingDir
	if staging == "" {
		staging = filepath.Join(a.ProgramDir, "backup", "native-staging")
	}
	if !filepath.IsAbs(staging) {
		return root, cleanup, errors.New("Staging-Verzeichnis muss absolut sein")
	}
	if err := os.MkdirAll(staging, 0700); err != nil {
		return root, cleanup, err
	}
	// ponytail: one full export on disk; stream when staging space becomes the bottleneck.
	temp, err := os.MkdirTemp(staging, "qdt-export-")
	if err != nil {
		return root, cleanup, err
	}
	cleanup = func() error { return os.RemoveAll(temp) }
	defer func() {
		if result != nil {
			result = errors.Join(result, cleanup())
		}
	}()
	if strings.HasPrefix(source, "database://mssql/") && runtime.GOOS != "windows" {
		if err := os.Chmod(temp, 0770); err != nil {
			return root, cleanup, err
		}
	}
	tool := backupNativeTool(source, c)
	output := filepath.Join(temp, "backup.dump")
	var cmd *exec.Cmd
	var stream bool
	switch {
	case strings.HasPrefix(source, "zfs:"):
		dataset := strings.TrimPrefix(source, "zfs://")
		snapshot := dataset + "@" + filepath.Base(temp)
		// Snapshot creation must finish before cleanup ownership is known, even on cancellation.
		createCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		err := backupNativeRun(createCtx, exec.CommandContext(createCtx, tool, "snapshot", snapshot), progress)
		cancel()
		if err != nil {
			return root, cleanup, err
		}
		defer func() {
			cleanCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if err := backupNativeRun(cleanCtx, exec.CommandContext(cleanCtx, tool, "destroy", snapshot), nil); err != nil {
				result = errors.Join(result, fmt.Errorf("Temporären ZFS-Snapshot %s manuell prüfen: %w", snapshot, err))
			}
		}()
		output = filepath.Join(temp, "backup.zfs")
		cmd = exec.CommandContext(ctx, tool, "send", "-w", "-p", snapshot)
		stream = true
	case strings.HasPrefix(source, "database://postgresql/"):
		cmd = exec.CommandContext(ctx, tool, "--no-password", "--format=custom", "--dbname=service="+c.Service)
		cmd.Env = append(os.Environ(), "PGSERVICEFILE="+c.ServiceFile)
		stream = true
	case strings.HasPrefix(source, "database://mariadb/") || strings.HasPrefix(source, "database://mysql/"):
		output = filepath.Join(temp, "backup.sql")
		// Global read lock also protects MyISAM/Aria tables. No concurrent DDL during export.
		cmd = exec.CommandContext(ctx, tool, "--defaults-file="+c.DefaultsFile, "--lock-all-tables", "--quick", "--skip-force", "--routines", "--events", "--triggers", "--hex-blob", "--databases", c.Database)
		stream = true
	case strings.HasPrefix(source, "database://mssql/"):
		output = filepath.Join(temp, "backup.bak")
		quote := func(s string) string { return "N'" + strings.ReplaceAll(s, "'", "''") + "'" }
		sql := "BACKUP DATABASE [" + strings.ReplaceAll(c.Database, "]", "]]") + "] TO DISK = " + quote(output) + " WITH COPY_ONLY, CHECKSUM; RESTORE VERIFYONLY FROM DISK = " + quote(output) + " WITH CHECKSUM;"
		args := []string{"-S", c.Server, "-b", "-r", "1", "-x", "-Q", sql}
		if c.Username == "" {
			args = append(args, "-E")
		} else {
			args = append(args, "-U", c.Username)
		}
		cmd = exec.CommandContext(ctx, tool, args...)
		if c.Username != "" {
			password, err := backupPrivateFile(c.PasswordFile)
			if err != nil {
				return root, cleanup, err
			}
			cmd.Env = append(os.Environ(), "SQLCMDPASSWORD="+strings.TrimRight(string(password), "\r\n"))
		}
	case isImage:
		// Killing wbadmin does not reliably stop the system backup. Finish it before deleting staging.
		cmd = exec.CommandContext(context.WithoutCancel(ctx), tool, "start", "backup", "-backupTarget:"+temp, "-allCritical", "-vssCopy", "-quiet")
		output = filepath.Join(temp, "WindowsImageBackup")
	}
	if err := ctx.Err(); err != nil {
		return root, cleanup, err
	}
	if stream {
		file, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return root, cleanup, err
		}
		cmd.Stdout = file
		err = backupNativeRun(ctx, cmd, progress)
		err = errors.Join(err, file.Close())
		if err != nil {
			return root, cleanup, err
		}
	} else if err := backupNativeRun(ctx, cmd, progress); err != nil {
		return root, cleanup, err
	}
	info, err := os.Lstat(output)
	if err != nil {
		return root, cleanup, errors.New("Backup-Werkzeug hat kein Archiv erstellt")
	}
	if isImage {
		images := 0
		err := filepath.WalkDir(output, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() && !entry.Type().IsRegular() {
				return errors.New("Unerwarteter Dateityp im Windows-Image")
			}
			if strings.EqualFold(filepath.Ext(path), ".vhdx") || strings.EqualFold(filepath.Ext(path), ".vhd") {
				images++
			}
			return nil
		})
		if err != nil || images == 0 {
			return root, cleanup, errors.New("Windows-Image enthält keine vollständige VHD/VHDX-Struktur")
		}
	} else if !info.Mode().IsRegular() || info.Size() == 0 {
		return root, cleanup, errors.New("Backup-Archiv ist leer oder keine reguläre Datei")
	}
	root = backupReadRoot{Original: filepath.Join("/native", strings.ReplaceAll(source, "://", "/"), filepath.Base(output)), Read: output}
	return root, cleanup, nil
}
