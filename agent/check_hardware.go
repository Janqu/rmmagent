package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
	"github.com/go-resty/resty/v2"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

type hardwareReading struct {
	Name   string   `json:"name"`
	State  string   `json:"state"`
	Value  *float64 `json:"value,omitempty"`
	Detail string   `json:"detail"`
}
type hardwareSample struct {
	Kind        string            `json:"kind"`
	CollectedAt time.Time         `json:"collected_at"`
	Readings    []hardwareReading `json:"readings"`
}

func hardwareUnknown(name, reason string) hardwareReading {
	return hardwareReading{Name: name, State: "unknown", Detail: reason}
}
func hardwareValue(name string, value float64, detail string) hardwareReading {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return hardwareUnknown(name, "Ungültiger Sensorwert")
	}
	return hardwareReading{Name: name, State: "ok", Value: &value, Detail: detail}
}

// Hardware checks report evidence; thresholds and alert transitions live on the server.
func (a *Agent) HardwareCheck(check rmm.Check, client *resty.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	kind := check.HardwareConfig.Kind
	readings := a.collectHardware(ctx, kind)
	if len(readings) == 0 {
		readings = []hardwareReading{hardwareUnknown(kind, "Keine unterstützten Messwerte verfügbar")}
	}
	if len(readings) > 255 {
		readings = append(readings[:255], hardwareUnknown("Erfassungslimit", "Mehr als 255 Sensoren; Erfassung unvollständig"))
	}
	sample := hardwareSample{Kind: kind, CollectedAt: time.Now().UTC(), Readings: readings}
	response, err := client.R().SetBody(map[string]any{"id": check.CheckPK, "agent_id": a.AgentID, "hardware": sample}).Patch("/api/v3/checkrunner/")
	if err != nil {
		a.Logger.Debugln("Hardware check delivery failed", err)
	} else if response.IsError() {
		a.Logger.Debugln("Hardware check rejected", response.StatusCode())
	}
}

func (a *Agent) collectHardware(ctx context.Context, kind string) []hardwareReading {
	out := []hardwareReading{}
	switch kind {
	case "temperature":
		for _, sensor := range a.TemperatureInventory() {
			name := sensor.Name + " [" + sensor.Source + "]"
			if sensor.Path != "" {
				name += " " + sensor.Path
			}
			out = append(out, hardwareValue(name, sensor.Celsius, "°C · "+sensor.Source))
		}
	case "memory":
		value, err := mem.VirtualMemoryWithContext(ctx)
		if err != nil || value.Total == 0 {
			return []hardwareReading{hardwareUnknown("RAM", "Speicherdaten nicht verfügbar")}
		}
		out = append(out, hardwareValue("RAM", 100*(1-float64(value.Available)/float64(value.Total)), fmt.Sprintf("%.1f GiB verfügbar", float64(value.Available)/(1<<30))))
	case "filesystem", "inodes":
		partitions, err := disk.PartitionsWithContext(ctx, false)
		if err != nil {
			return []hardwareReading{hardwareUnknown("Dateisysteme", "Auflistung fehlgeschlagen")}
		}
		for _, part := range partitions {
			if strings.HasPrefix(part.Device, "/dev/loop") || part.Fstype == "squashfs" {
				continue
			}
			use, err := disk.UsageWithContext(ctx, part.Mountpoint)
			if err != nil {
				out = append(out, hardwareUnknown(part.Mountpoint, "Nutzungsdaten nicht lesbar"))
				continue
			}
			if kind == "inodes" {
				if use.InodesTotal > 0 {
					out = append(out, hardwareValue(part.Mountpoint, use.InodesUsedPercent, "% Inodes belegt"))
				}
			} else if use.Total > 0 {
				out = append(out, hardwareValue(part.Mountpoint, use.UsedPercent, fmt.Sprintf("%.1f GiB frei", float64(use.Free)/(1<<30))))
			}
		}
	case "smart":
		return collectSMART(ctx)
	case "zfs":
		raw, err := hardwareCommand(ctx, "zpool", "list", "-H", "-p", "-o", "name,health,capacity")
		if err != nil {
			return []hardwareReading{hardwareUnknown("ZFS", "zpool nicht verfügbar oder Abfrage fehlgeschlagen")}
		}
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			state := "ok"
			health := strings.ToUpper(fields[1])
			switch health {
			case "ONLINE":
			case "DEGRADED":
				state = "warning"
			case "FAULTED", "OFFLINE", "UNAVAIL", "REMOVED", "SUSPENDED":
				state = "error"
			default:
				state = "unknown"
			}
			capacity, err := strconv.ParseFloat(strings.TrimSuffix(fields[2], "%"), 64)
			if err != nil || math.IsNaN(capacity) || math.IsInf(capacity, 0) || capacity < 0 || capacity > 100 {
				if state != "error" {
					state = "unknown"
				}
			} else if capacity >= 95 {
				state = "error"
			} else if capacity >= 80 && state == "ok" {
				state = "warning"
			}
			out = append(out, hardwareReading{Name: fields[0], State: state, Detail: fmt.Sprintf("%s · Belegung %s%% (Warnung 80%%, Fehler 95%%)", health, fields[2])})
		}
	case "raid", "ecc":
		if runtime.GOOS != "linux" {
			return []hardwareReading{hardwareUnknown(kind, "Diese Prüfung benötigt Linux-sysfs")}
		}
		return linuxHardwareCounters(kind, "/sys")
	default:
		out = append(out, hardwareUnknown(kind, "Unbekannte Hardware-Prüfung"))
	}
	return out
}

// Bound subprocess runtime and output; arguments are fixed or come from local device discovery.
type hardwareOutput struct{ bytes.Buffer }

func (b *hardwareOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 2<<20 {
		return 0, io.ErrShortWrite
	}
	return b.Buffer.Write(p)
}
func hardwareCommand(parent context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	var output hardwareOutput
	cmd.Stdout = &output
	err := cmd.Run()
	return output.Bytes(), err
}

func linuxHardwareCounters(kind, root string) []hardwareReading {
	out := []hardwareReading{}
	pattern := "block/md*/md"
	if kind == "ecc" {
		pattern = "devices/system/edac/mc/mc*"
	}
	paths, _ := filepath.Glob(filepath.Join(root, pattern))
	for _, path := range paths {
		read := func(name string) (uint64, error) {
			b, e := os.ReadFile(filepath.Join(path, name))
			if e != nil {
				return 0, e
			}
			return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		}
		if kind == "raid" {
			degraded, err := read("degraded")
			stateBytes, stateErr := os.ReadFile(filepath.Join(path, "array_state"))
			name := filepath.Base(filepath.Dir(path))
			if err != nil || stateErr != nil {
				out = append(out, hardwareUnknown(name, "RAID-Zustand nicht lesbar"))
				continue
			}
			arrayState := strings.TrimSpace(string(stateBytes))
			state := "ok"
			switch arrayState {
			case "active", "clean", "active-idle", "write-pending", "read-auto":
			case "readonly":
				state = "warning"
			case "inactive", "clear", "suspended":
				state = "error"
			default:
				state = "unknown"
			}
			if degraded > 0 {
				state = "error"
			}
			syncBytes, _ := os.ReadFile(filepath.Join(path, "sync_action"))
			sync := strings.TrimSpace(string(syncBytes))
			if state == "ok" && sync != "" && sync != "idle" {
				state = "warning"
			}
			out = append(out, hardwareReading{Name: name, State: state, Detail: fmt.Sprintf("%s · fehlende Mitglieder: %d · %s", arrayState, degraded, sync)})
		} else {
			ce, e1 := read("ce_count")
			ue, e2 := read("ue_count")
			name := filepath.Base(path)
			if e1 != nil || e2 != nil {
				out = append(out, hardwareUnknown(name, "ECC-Zähler nicht lesbar"))
				continue
			}
			state := "ok"
			if ue > 0 {
				state = "error"
			} else if ce > 0 {
				state = "warning"
			}
			out = append(out, hardwareReading{Name: name, State: state, Detail: fmt.Sprintf("ECC seit Boot: korrigiert %d, nicht korrigierbar %d", ce, ue)})
		}
	}
	return out
}

func collectSMART(ctx context.Context) []hardwareReading {
	path, err := exec.LookPath("smartctl")
	if err != nil && runtime.GOOS == "windows" {
		candidate := filepath.Join(os.Getenv("ProgramFiles"), "smartmontools", "bin", "smartctl.exe")
		if info, e := os.Stat(candidate); e == nil && !info.IsDir() {
			path = candidate
			err = nil
		}
	}
	if err != nil {
		return []hardwareReading{hardwareUnknown("SMART", "smartctl fehlt; keine Datenträger-Gesundheitsprüfung möglich")}
	}
	raw, err := hardwareCommand(ctx, path, "--scan", "-j")
	var scan struct {
		Devices []struct{ Name, Type string } `json:"devices"`
	}
	if err != nil || json.Unmarshal(raw, &scan) != nil {
		return []hardwareReading{hardwareUnknown("SMART", "Datenträger-Auflistung fehlgeschlagen")}
	}
	out := []hardwareReading{}
	for i, device := range scan.Devices {
		if i >= 32 || ctx.Err() != nil {
			out = append(out, hardwareUnknown("SMART", "Erfassung unvollständig: Zeit- oder Gerätelimit erreicht"))
			break
		}
		if device.Name == "" || strings.HasPrefix(device.Name, "-") || len(device.Name) > 256 || len(device.Type) > 128 {
			out = append(out, hardwareUnknown("SMART", "Ungültige Gerätekennung"))
			continue
		}
		args := []string{"-a", "-j", "-n", "standby"}
		if device.Type != "" {
			args = append(args, "-d", device.Type)
		}
		args = append(args, device.Name)
		data, commandErr := hardwareCommand(ctx, path, args...)
		name := device.Name
		if device.Type != "" {
			name += " (" + device.Type + ")"
		}
		reading := parseSMART(name, data)
		if commandErr != nil && reading.State == "ok" {
			reading = hardwareUnknown(name, "SMART-Abfrage unvollständig")
		}
		out = append(out, reading)
	}
	return out
}

func parseSMART(name string, raw []byte) hardwareReading {
	var data struct {
		Smartctl struct {
			ExitStatus int `json:"exit_status"`
		} `json:"smartctl"`
		Status struct {
			Passed *bool `json:"passed"`
		} `json:"smart_status"`
		NVMe *struct {
			Critical *uint64 `json:"critical_warning"`
			Media    uint64  `json:"media_errors"`
			Used     uint64  `json:"percentage_used"`
		} `json:"nvme_smart_health_information_log"`
		ATA struct {
			Table []struct {
				ID  int `json:"id"`
				Raw struct {
					Value uint64 `json:"value"`
				} `json:"raw"`
			} `json:"table"`
		} `json:"ata_smart_attributes"`
	}
	if json.Unmarshal(raw, &data) != nil {
		return hardwareUnknown(name, "SMART-JSON nicht lesbar")
	}
	state := "ok"
	messages := []string{}
	if data.Status.Passed == nil && (data.NVMe == nil || data.NVMe.Critical == nil) {
		return hardwareUnknown(name, "SMART-Gesundheitsstatus fehlt (ggf. Standby oder nicht unterstützt)")
	}
	if (data.Status.Passed != nil && !*data.Status.Passed) || data.Smartctl.ExitStatus&24 != 0 {
		state = "error"
		messages = append(messages, "SMART meldet einen kritischen Zustand")
	}
	if data.NVMe != nil && data.NVMe.Critical != nil {
		n := data.NVMe
		messages = append(messages, fmt.Sprintf("NVMe: Warnbits %d, Medienfehler %d, Lebensdauer verbraucht %d%%", *n.Critical, n.Media, n.Used))
		if *n.Critical != 0 || n.Media > 0 || n.Used >= 100 {
			state = "error"
		} else if n.Used >= 90 && state == "ok" {
			state = "warning"
		}
	}
	for _, attr := range data.ATA.Table {
		if attr.Raw.Value == 0 {
			continue
		}
		switch attr.ID {
		case 197, 198:
			state = "error"
			messages = append(messages, fmt.Sprintf("ATA %d: %d nicht stabile/korrigierbare Sektoren", attr.ID, attr.Raw.Value))
		case 5:
			if state == "ok" {
				state = "warning"
			}
			messages = append(messages, fmt.Sprintf("Neu zugewiesene Sektoren: %d", attr.Raw.Value))
		}
	}
	if data.Smartctl.ExitStatus&224 != 0 {
		if state == "ok" {
			state = "warning"
		}
		messages = append(messages, "SMART enthält frühere Attribut-, Fehler- oder Selbsttestmeldungen")
	}
	if data.Smartctl.ExitStatus&7 != 0 {
		if state != "error" {
			state = "unknown"
		}
		messages = append(messages, "Abfrage war unvollständig")
	}
	if len(messages) == 0 {
		messages = append(messages, "SMART-Gesundheitsstatus bestanden")
	}
	return hardwareReading{Name: name, State: state, Detail: strings.Join(messages, "; ")}
}
