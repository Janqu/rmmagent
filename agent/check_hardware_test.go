package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHardwareSMART(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"missing", `{}`, "unknown"},
		{"healthy", `{"smart_status":{"passed":true}}`, "ok"},
		{"failed", `{"smart_status":{"passed":false}}`, "error"},
		{"partial", `{"smart_status":{"passed":true},"smartctl":{"exit_status":4}}`, "unknown"},
		{"pending sector", `{"smart_status":{"passed":true},"ata_smart_attributes":{"table":[{"id":197,"raw":{"value":1}}]}}`, "error"},
		{"reallocated", `{"smart_status":{"passed":true},"ata_smart_attributes":{"table":[{"id":5,"raw":{"value":1}}]}}`, "warning"},
		{"nvme wear", `{"nvme_smart_health_information_log":{"critical_warning":0,"percentage_used":92}}`, "warning"},
		{"nvme media", `{"nvme_smart_health_information_log":{"critical_warning":0,"media_errors":1}}`, "error"},
		{"nvme no status", `{"nvme_smart_health_information_log":{"percentage_used":0}}`, "unknown"},
		{"nvme healthy", `{"nvme_smart_health_information_log":{"critical_warning":0,"percentage_used":12}}`, "ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseSMART("disk", []byte(tc.body)); got.State != tc.want {
				t.Fatalf("%+v want %s", got, tc.want)
			}
		})
	}
}

func TestHardwareCounters(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "block/md0/md")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(path, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("degraded", "1")
	write("array_state", "active")
	write("sync_action", "recover")
	if got := linuxHardwareCounters("raid", root); len(got) != 1 || got[0].State != "error" {
		t.Fatal(got)
	}
	write("degraded", "0")
	write("sync_action", "idle")
	if got := linuxHardwareCounters("raid", root); len(got) != 1 || got[0].State != "ok" {
		t.Fatal(got)
	}
	write("degraded", "invalid")
	if got := linuxHardwareCounters("raid", root); len(got) != 1 || got[0].State != "unknown" {
		t.Fatal(got)
	}
	path = filepath.Join(root, "devices/system/edac/mc/mc0")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	write("ce_count", "0")
	write("ue_count", "1")
	if got := linuxHardwareCounters("ecc", root); len(got) != 1 || got[0].State != "error" {
		t.Fatal(got)
	}
}

func TestHardwareSysfsTemperature(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want float64
	}{{"55000", 55}, {"1000", 1}, {"500", 0.5}, {"-1000", -1}} {
		got, ok := parseSysfsTemperature(tc.raw)
		if !ok || got != tc.want {
			t.Fatalf("%s: %v %v", tc.raw, got, ok)
		}
	}
	for _, raw := range []string{"NaN", "Inf", "garbage", "201000"} {
		if _, ok := parseSysfsTemperature(raw); ok {
			t.Fatal(raw)
		}
	}
}
