//go:build windows

package agent

import rmm "github.com/Janqu/qdt-rmm-agent/shared"

type msAcpiThermalZoneTemperature struct {
	InstanceName       string
	CurrentTemperature uint32
}

func (a *Agent) TemperatureInventory() []rmm.TemperatureSensorInventory {
	var zones []msAcpiThermalZoneTemperature
	if err := wmiQueryNamespace("SELECT InstanceName, CurrentTemperature FROM MSAcpi_ThermalZoneTemperature", &zones, `ROOT\WMI`); err != nil {
		return []rmm.TemperatureSensorInventory{}
	}
	sensors := make([]rmm.TemperatureSensorInventory, 0, len(zones))
	for _, zone := range zones {
		if zone.CurrentTemperature == 0 {
			continue
		}
		celsius := float64(zone.CurrentTemperature)/10 - 273.15
		if celsius < -100 || celsius > 200 {
			continue
		}
		sensors = append(sensors, temperatureSensor(sensorName(zone.InstanceName), "acpi", "", celsius))
	}
	return sensors
}
