package agent

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

func temperatureSensor(name, source, path string, celsius float64) rmm.TemperatureSensorInventory {
	return rmm.TemperatureSensorInventory{
		Name:       strings.TrimSpace(name),
		Source:     source,
		Path:       path,
		Celsius:    celsius,
		Fahrenheit: celsius*9/5 + 32,
	}
}

func parseSysfsTemperature(raw string) (float64, bool) {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	value /= 1000
	return value, err == nil && !math.IsNaN(value) && !math.IsInf(value, 0) && value >= -100 && value <= 200
}

func parseMilliCelsius(raw string) (float64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false
	}
	if value > 1000 {
		value = value / 1000
	}
	if math.IsNaN(value) || math.IsInf(value, 0) || value < -100 || value > 200 {
		return 0, false
	}
	return value, true
}

func sensorName(parts ...string) string {
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			return part
		}
	}
	return "temperature"
}

func numberedSensorName(prefix string, n int) string {
	if prefix == "" {
		prefix = "temperature"
	}
	return fmt.Sprintf("%s %d", prefix, n)
}

func parseFreeBSDTemperatures(output string) []rmm.TemperatureSensorInventory {
	var sensors []rmm.TemperatureSensorInventory
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), "C"))
		if !strings.Contains(strings.ToLower(key), "temperature") {
			continue
		}
		celsius, ok := parseMilliCelsius(value)
		if !ok {
			continue
		}
		sensors = append(sensors, temperatureSensor(key, "sysctl", "", celsius))
	}
	return sensors
}
