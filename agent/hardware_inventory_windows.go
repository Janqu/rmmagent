//go:build windows

package agent

import (
	"strings"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
	"github.com/StackExchange/wmi"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

type win32PhysicalMemoryArray struct {
	MemoryDevices uint16
}

type win32PhysicalMemorySlot struct {
	Capacity uint64
}

func (a *Agent) HardwareInventory() rmm.HardwareInventory {
	return rmm.HardwareInventory{
		Disks:        windowsDiskHealth(),
		Partitions:   windowsPartitionHealth(),
		Memory:       windowsMemoryHealth(),
		Temperatures: a.TemperatureInventory(),
	}
}

func windowsDiskHealth() []rmm.DiskHealthInventory {
	var drives []rmm.Win32_DiskDrive
	if err := wmi.Query("SELECT * FROM Win32_DiskDrive", &drives); err != nil {
		return nil
	}
	out := make([]rmm.DiskHealthInventory, 0, len(drives))
	for _, d := range drives {
		status := strings.TrimSpace(d.Status)
		out = append(out, rmm.DiskHealthInventory{
			Name:      firstNonEmpty(d.DeviceID, d.Name, d.Caption),
			Model:     strings.TrimSpace(d.Model),
			Vendor:    strings.TrimSpace(d.Manufacturer),
			Serial:    strings.TrimSpace(d.SerialNumber),
			SizeBytes: d.Size,
			Status:    status,
			Healthy:   status == "" || strings.EqualFold(status, "OK"),
			Source:    "wmi",
		})
	}
	return out
}

func windowsPartitionHealth() []rmm.PartitionHealthInventory {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return nil
	}
	out := make([]rmm.PartitionHealthInventory, 0, len(partitions))
	for _, p := range partitions {
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		out = append(out, rmm.PartitionHealthInventory{
			Device:     p.Device,
			Mountpoint: p.Mountpoint,
			Fstype:     p.Fstype,
			TotalBytes: usage.Total,
			UsedBytes:  usage.Used,
			FreeBytes:  usage.Free,
			UsedPct:    usage.UsedPercent,
			Healthy:    healthyPartition(usage.UsedPercent),
		})
	}
	return out
}

func windowsMemoryHealth() rmm.MemoryHealthInventory {
	vm, err := mem.VirtualMemory()
	if err != nil {
		return rmm.MemoryHealthInventory{}
	}
	total, used := windowsMemorySlots()
	return memoryInventory(vm.Total, vm.Used, vm.Available, vm.UsedPercent, total, used, "wmi")
}

func windowsMemorySlots() (int, int) {
	var arrays []win32PhysicalMemoryArray
	total := 0
	if err := wmi.Query("SELECT MemoryDevices FROM Win32_PhysicalMemoryArray", &arrays); err == nil {
		for _, array := range arrays {
			total += int(array.MemoryDevices)
		}
	}

	var slots []win32PhysicalMemorySlot
	used := 0
	if err := wmi.Query("SELECT Capacity FROM Win32_PhysicalMemory", &slots); err == nil {
		for _, slot := range slots {
			if slot.Capacity > 0 {
				used++
			}
		}
	}
	return total, used
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return "disk"
}
