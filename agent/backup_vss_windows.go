package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/StackExchange/wmi"
	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

func backupVSSExecutable() string {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return ""
	}
	// 32-bit agents on 64-bit Windows must use the native VSS requester.
	if native := filepath.Join(filepath.Dir(system), "Sysnative", "diskshadow.exe"); fileExists(native) {
		return native
	}
	return filepath.Join(system, "diskshadow.exe")
}
func backupVSSAvailable() bool { return fileExists(backupVSSExecutable()) }

func backupVSSRoots(paths []string) ([]backupReadRoot, []string, error) {
	if len(paths) == 0 || len(paths) > 100 {
		return nil, nil, errors.New("VSS benötigt 1–100 lokale Quellpfade")
	}
	var roots []backupReadRoot
	var volumes []string
	seen := map[string]bool{}
	getVolumePath := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetVolumePathNameW")
	for _, path := range paths {
		path = filepath.Clean(path)
		if len(path) < 3 || path[1:3] != `:\` || !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) {
			return nil, nil, errors.New("VSS unterstützt hier nur absolute lokale Laufwerkspfade, keine UNC-Freigaben")
		}
		// Reject source symlinks/junctions, including a junction in a parent path.
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, nil, err
		}
		if !strings.EqualFold(filepath.Clean(resolved), path) {
			return nil, nil, fmt.Errorf("VSS-Quelle ist eine Verknüpfung: %s", path)
		}
		volume := strings.ToUpper(path[:1]) + `:\`
		vp, _ := windows.UTF16PtrFromString(volume)
		if windows.GetDriveType(vp) != windows.DRIVE_FIXED {
			return nil, nil, fmt.Errorf("VSS benötigt ein lokales festes Laufwerk: %s", volume)
		}
		pp, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, nil, err
		}
		buffer := make([]uint16, windows.MAX_PATH)
		ok, _, callErr := getVolumePath.Call(uintptr(unsafe.Pointer(pp)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
		if ok == 0 {
			return nil, nil, callErr
		}
		if !strings.EqualFold(windows.UTF16ToString(buffer), volume) {
			return nil, nil, errors.New("VSS-Mountpoints benötigen einen eigenen Laufwerksbuchstaben")
		}
		if !seen[volume] {
			volumes = append(volumes, volume)
			seen[volume] = true
		}
		roots = append(roots, backupReadRoot{Original: volume + path[3:]})
	}
	return roots, volumes, nil
}

// Diskshadow owns a volatile, writer-free snapshot set for this file backup.
// A kill-on-close Windows job ties its whole process tree to the agent lifetime.
func (a *Agent) backupVSS(ctx context.Context, paths []string) (*backupSnapshot, []backupReadRoot, func() error, error) {
	roots, volumes, err := backupVSSRoots(paths)
	if err != nil {
		return nil, nil, nil, err
	}
	if !backupVSSAvailable() {
		return nil, nil, nil, errors.New("Windows Diskshadow ist nicht verfügbar")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, nil, err
	}
	if strings.ContainsAny(exe, "%\r\n\"!") {
		return nil, nil, nil, errors.New("Agent-Pfad ist für VSS ungeeignet")
	}
	dir := filepath.Join(a.ProgramDir, "qdt-vss-"+uuid.NewString())
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return nil, nil, nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	dp, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	if err = windows.CreateDirectory(dp, &sa); err != nil {
		return nil, nil, nil, err
	}
	remove := func() { _ = os.RemoveAll(dir) }
	for name, contents := range map[string]string{
		"gate.cmd": "@echo off\r\n\"" + exe + "\" --backup-vss-helper gate\r\nexit /b %errorlevel%\r\n",
		"hold.cmd": "@echo off\r\n\"" + exe + "\" --backup-vss-helper hold\r\nexit /b %errorlevel%\r\n",
	} {
		if err = os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			remove()
			return nil, nil, nil, err
		}
	}
	raw, _ := json.Marshal(volumes)
	if err = os.WriteFile(filepath.Join(dir, "volumes.json"), raw, 0600); err != nil {
		remove()
		return nil, nil, nil, err
	}
	script := "exec gate.cmd\r\nset context volatile nowriters\r\n"
	for i, v := range volumes {
		script += fmt.Sprintf("add volume %s alias qdtvss%d\r\n", v, i)
	}
	script += "create\r\nexec hold.cmd\r\nexit\r\n"
	if err = os.WriteFile(filepath.Join(dir, "snapshot.dsh"), []byte(script), 0600); err != nil {
		remove()
		return nil, nil, nil, err
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		remove()
		return nil, nil, nil, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)))
	if err != nil {
		windows.CloseHandle(job)
		remove()
		return nil, nil, nil, err
	}
	log, err := os.Create(filepath.Join(dir, "diskshadow.log"))
	if err != nil {
		windows.CloseHandle(job)
		remove()
		return nil, nil, nil, err
	}
	cmd := exec.Command(backupVSSExecutable(), "/s", "snapshot.dsh")
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err = cmd.Start(); err != nil {
		log.Close()
		windows.CloseHandle(job)
		remove()
		return nil, nil, nil, err
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(done) }()
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, process)
		windows.CloseHandle(process)
	}
	if err != nil {
		_ = cmd.Process.Kill()
		<-done
		log.Close()
		windows.CloseHandle(job)
		remove()
		return nil, nil, nil, err
	}
	var once sync.Once
	var cleanupErr error
	cleanup := func() error {
		once.Do(func() {
			_ = os.WriteFile(filepath.Join(dir, "release"), nil, 0600)
			select {
			case <-done:
				cleanupErr = waitErr
			case <-time.After(30 * time.Second):
				cleanupErr = errors.New("VSS-Prozess musste nach Zeitlimit beendet werden")
			}
			windows.CloseHandle(job)
			if cleanupErr != nil {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
				}
			}
			log.Close()
			remove()
		})
		return cleanupErr
	}
	if err = os.WriteFile(filepath.Join(dir, "start"), nil, 0600); err != nil {
		cleanup()
		return nil, nil, nil, err
	}
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			cleanup()
			return nil, nil, nil, ctx.Err()
		case <-timer.C:
			cleanup()
			return nil, nil, nil, errors.New("Schattenkopie nach 120 Sekunden nicht bereit")
		case <-done:
			raw, _ := os.ReadFile(filepath.Join(dir, "diskshadow.log"))
			if len(raw) > 3000 {
				raw = raw[len(raw)-3000:]
			}
			cleanup()
			return nil, nil, nil, fmt.Errorf("Schattenkopie fehlgeschlagen (%v): %s", waitErr, string(raw))
		case <-tick.C:
			raw, err := os.ReadFile(filepath.Join(dir, "ready.json"))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				cleanup()
				return nil, nil, nil, err
			}
			var snapshot backupSnapshot
			if json.Unmarshal(raw, &snapshot) != nil || len(snapshot.Volumes) != len(volumes) {
				cleanup()
				return nil, nil, nil, errors.New("Unvollständiges VSS-Snapshot-Set")
			}
			for i := range roots {
				for _, v := range snapshot.Volumes {
					if roots[i].Original[:3] == v.Volume {
						roots[i].Read = v.Device + `\` + roots[i].Original[3:]
					}
				}
				if roots[i].Read == "" {
					cleanup()
					return nil, nil, nil, errors.New("VSS-Quelle fehlt im Snapshot-Set")
				}
			}
			return &snapshot, roots, cleanup, nil
		}
	}
}

// Invoked only by our private Diskshadow scripts. No RMM credentials are loaded.
func BackupVSSHelper(stage string) error {
	if stage != "gate" && stage != "hold" {
		return errors.New("invalid VSS helper stage")
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(filepath.Base(dir), "qdt-vss-") {
		return errors.New("invalid VSS working directory")
	}
	marker := "start"
	if stage == "hold" {
		raw, err := os.ReadFile("volumes.json")
		if err != nil {
			return err
		}
		var volumes []string
		if json.Unmarshal(raw, &volumes) != nil || len(volumes) == 0 || len(volumes) > 26 {
			return errors.New("invalid VSS volume list")
		}
		var shadows []struct{ ID, SetID, DeviceObject string }
		if err = wmi.Query("SELECT ID,SetID,DeviceObject FROM Win32_ShadowCopy", &shadows); err != nil {
			return err
		}
		snapshot := backupSnapshot{Mode: "required", Status: "reading", CreatedAt: time.Now().UTC()}
		setID := ""
		for i, volume := range volumes {
			id := os.Getenv("qdtvss" + strconv.Itoa(i))
			found := false
			for _, shadow := range shadows {
				if strings.EqualFold(id, shadow.ID) && id != "" {
					if !strings.HasPrefix(shadow.DeviceObject, `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy`) || (setID != "" && setID != shadow.SetID) {
						return errors.New("invalid VSS snapshot device or set")
					}
					setID = shadow.SetID
					snapshot.Volumes = append(snapshot.Volumes, backupSnapshotVolume{Volume: volume, ID: id, Device: shadow.DeviceObject})
					found = true
					break
				}
			}
			if !found {
				return errors.New("missing VSS snapshot alias")
			}
		}
		raw, _ = json.Marshal(snapshot)
		if err = os.WriteFile("ready.tmp", raw, 0600); err != nil {
			return err
		}
		if err = os.Rename("ready.tmp", "ready.json"); err != nil {
			return err
		}
		marker = "release"
	}
	deadline := time.Now().Add(72 * time.Hour)
	if stage == "gate" {
		deadline = time.Now().Add(30 * time.Second)
	}
	for time.Now().Before(deadline) {
		if fileExists(marker) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("VSS helper timeout")
}
