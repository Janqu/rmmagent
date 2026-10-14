//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

func (a *Agent) TemperatureInventory() []rmm.TemperatureSensorInventory {
	switch runtime.GOOS {
	case "linux":
		return linuxTemperatureInventory()
	case "freebsd":
		return freebsdTemperatureInventory()
	default:
		return []rmm.TemperatureSensorInventory{}
	}
}

func linuxTemperatureInventory() []rmm.TemperatureSensorInventory {
	var sensors []rmm.TemperatureSensorInventory
	sensors = append(sensors, linuxHwmonTemperatures()...)
	sensors = append(sensors, linuxThermalZoneTemperatures()...)
	return dedupeTemperatureSensors(sensors)
}

func linuxHwmonTemperatures() []rmm.TemperatureSensorInventory {
	return linuxHwmonTemperaturesAt("/sys/class/hwmon")
}

func linuxHwmonTemperaturesAt(root string) []rmm.TemperatureSensorInventory {
	hwmons, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var sensors []rmm.TemperatureSensorInventory
	for _, hwmon := range hwmons {
		if info, err := os.Stat(filepath.Join(root, hwmon.Name())); err != nil || !info.IsDir() {
			continue
		}
		dir := filepath.Join(root, hwmon.Name())
		chip := readFirstLine(filepath.Join(dir, "name"))
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(name, "temp") || !strings.HasSuffix(name, "_input") {
				continue
			}
			raw := readFirstLine(filepath.Join(dir, name))
			celsius, ok := parseSysfsTemperature(raw)
			if !ok {
				continue
			}
			num := strings.TrimSuffix(strings.TrimPrefix(name, "temp"), "_input")
			label := readFirstLine(filepath.Join(dir, "temp"+num+"_label"))
			sensors = append(sensors, temperatureSensor(sensorName(label, numberedSensorName(chip, atoiDefault(num, 1))), "hwmon", filepath.Join(dir, name), celsius))
		}
	}
	return sensors
}

func linuxThermalZoneTemperatures() []rmm.TemperatureSensorInventory {
	zones, err := os.ReadDir("/sys/class/thermal")
	if err != nil {
		return nil
	}
	var sensors []rmm.TemperatureSensorInventory
	for _, zone := range zones {
		if info, err := os.Stat(filepath.Join("/sys/class/thermal", zone.Name())); err != nil || !info.IsDir() || !strings.HasPrefix(zone.Name(), "thermal_zone") {
			continue
		}
		dir := filepath.Join("/sys/class/thermal", zone.Name())
		raw := readFirstLine(filepath.Join(dir, "temp"))
		celsius, ok := parseSysfsTemperature(raw)
		if !ok {
			continue
		}
		name := sensorName(readFirstLine(filepath.Join(dir, "type")), zone.Name())
		sensors = append(sensors, temperatureSensor(name, "thermal_zone", filepath.Join(dir, "temp"), celsius))
	}
	return sensors
}

func freebsdTemperatureInventory() []rmm.TemperatureSensorInventory {
	out, err := runPatchInventoryCommand("sysctl", "-a")
	if err != nil {
		return []rmm.TemperatureSensorInventory{}
	}
	return parseFreeBSDTemperatures(out)
}

func readFirstLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(data), "\n")
	return strings.TrimSpace(line)
}

func atoiDefault(value string, fallback int) int {
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

func dedupeTemperatureSensors(in []rmm.TemperatureSensorInventory) []rmm.TemperatureSensorInventory {
	seen := map[string]bool{}
	out := make([]rmm.TemperatureSensorInventory, 0, len(in))
	for _, sensor := range in {
		key := strings.ToLower(sensor.Source + "|" + sensor.Path + "|" + sensor.Name)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, sensor)
	}
	return out
}
