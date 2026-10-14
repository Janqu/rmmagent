package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

type proxmoxGuest struct {
	VMID     int     `json:"vmid"`
	Type     string  `json:"type"`
	Name     string  `json:"name"`
	Status   string  `json:"status"`
	CPUs     int     `json:"cpus"`
	CPU      float64 `json:"cpu"`
	Mem      int64   `json:"mem"`
	MaxMem   int64   `json:"maxmem"`
	MaxDisk  int64   `json:"maxdisk"`
	Uptime   int64   `json:"uptime"`
	Template int     `json:"template"`
}

type proxmoxInventory struct {
	Node        string         `json:"node"`
	Version     string         `json:"version"`
	CollectedAt string         `json:"collected_at"`
	Guests      []proxmoxGuest `json:"guests"`
	Errors      []string       `json:"errors"`
}

var proxmoxNodeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

func proxmoxNode(configDir string) string {
	real, err := filepath.EvalSymlinks(configDir)
	if err != nil || filepath.Base(filepath.Dir(real)) != "nodes" || !proxmoxNodeName.MatchString(filepath.Base(real)) {
		return ""
	}
	if info, err := os.Stat(real); err != nil || !info.IsDir() {
		return ""
	}
	return filepath.Base(real)
}

func collectProxmox() *proxmoxInventory {
	if runtime.GOOS != "linux" {
		return nil
	}
	versionTool, err := exec.LookPath("pveversion")
	node := proxmoxNode(backupProxmoxConfig)
	if err != nil || node == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return readProxmoxInventory(ctx, node, versionTool, "pvesh")
}

func proxmoxCommand(ctx context.Context, tool string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, tool, args...)
	stdout, stderr := newCappedBuffer(1<<20), newCappedBuffer(1024)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if stdout.truncated {
		return nil, fmt.Errorf("Proxmox-Ausgabe überschreitet 1 MiB")
	}
	return stdout.buf.Bytes(), nil
}

func readProxmoxInventory(ctx context.Context, node, versionTool, apiTool string) *proxmoxInventory {
	inventory := &proxmoxInventory{Node: node, CollectedAt: time.Now().UTC().Format(time.RFC3339), Guests: []proxmoxGuest{}, Errors: []string{}}
	version, err := proxmoxCommand(ctx, versionTool)
	if err != nil {
		inventory.Errors = append(inventory.Errors, "Version: "+err.Error())
	} else {
		parts := strings.Split(strings.TrimSpace(string(version)), "/")
		if len(parts) >= 2 && parts[0] == "pve-manager" && len(parts[1]) <= 80 {
			inventory.Version = parts[1]
		}
	}
	for _, kind := range []string{"qemu", "lxc"} {
		raw, err := proxmoxCommand(ctx, apiTool, "get", "/nodes/"+node+"/"+kind, "--output-format", "json")
		var guests []proxmoxGuest
		if err == nil {
			err = json.Unmarshal(raw, &guests)
			if err == nil && (guests == nil || len(guests) > 1000) {
				err = fmt.Errorf("Ungültige Gästeliste oder mehr als 1000 Gäste")
			}
		}
		if err != nil {
			inventory.Errors = append(inventory.Errors, kind+": "+err.Error())
			continue
		}
		seen := make(map[int]bool)
		for _, guest := range guests {
			if guest.VMID < 100 || guest.VMID > 999999999 || seen[guest.VMID] || len(guest.Name) > 255 || len(guest.Status) > 40 || guest.CPUs < 0 || guest.CPU < 0 || guest.Mem < 0 || guest.MaxMem < 0 || guest.MaxDisk < 0 || guest.Uptime < 0 || (guest.Template != 0 && guest.Template != 1) {
				inventory.Errors = append(inventory.Errors, kind+": Ungültiger Gasteintrag")
				continue
			}
			seen[guest.VMID] = true
			guest.Type = kind
			inventory.Guests = append(inventory.Guests, guest)
		}
	}
	sort.Slice(inventory.Guests, func(i, j int) bool { return inventory.Guests[i].VMID < inventory.Guests[j].VMID })
	return inventory
}
