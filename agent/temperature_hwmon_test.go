//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHardwareHwmonSymlink(t *testing.T) {
	root, device := t.TempDir(), t.TempDir()
	for name, value := range map[string]string{"name": "coretemp", "temp1_input": "500", "temp1_label": "CPU"} {
		if err := os.WriteFile(filepath.Join(device, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(device, filepath.Join(root, "hwmon0")); err != nil {
		t.Fatal(err)
	}
	got := linuxHwmonTemperaturesAt(root)
	if len(got) != 1 || got[0].Name != "CPU" || got[0].Celsius != 0.5 {
		t.Fatalf("missed hwmon symlink: %+v", got)
	}
}
