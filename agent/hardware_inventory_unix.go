//go:build !windows

package agent

import (
	"path/filepath"
	"strings"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
	"github.com/jaypipes/ghw"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

func (a *Agent) HardwareInventory() rmm.HardwareInventory {
	return rmm.HardwareInventory{
		Disks:        unixDiskHealth(),
		Partitions:   partitionHealth(),
		ZFSPools:     zfsHealth(),
		Memory:       unixMemoryHealth(),
		Temperatures: a.TemperatureInventory(),
	}
}

func partitionHealth() []rmm.PartitionHealthInventory {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return nil
	}
	out := make([]rmm.PartitionHealthInventory, 0, len(partitions))
	for _, p := range partitions {
		if strings.Contains(p.Device, "dev/loop") || strings.Contains(p.Device, "devfs") {
			continue
		}
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

func unixDiskHealth() []rmm.DiskHealthInventory {
	block, err := ghw.Block(ghw.WithDisableWarnings())
	if err != nil {
		return linuxSysBlockHealth()
	}
	out := make([]rmm.DiskHealthInventory, 0, len(block.Disks))
	for _, d := range block.Disks {
		if d.IsRemovable || strings.Contains(d.Name, "loop") || strings.Contains(d.Name, "ram") {
			continue
		}
		out = append(out, rmm.DiskHealthInventory{
			Name:      d.Name,
			Model:     strings.TrimSpace(d.Model),
			Vendor:    strings.TrimSpace(d.Vendor),
			Serial:    strings.TrimSpace(d.SerialNumber),
			SizeBytes: d.SizeBytes,
			Status:    "present",
			Healthy:   true,
			Source:    "ghw",
		})
	}
	if len(out) == 0 {
		return linuxSysBlockHealth()
	}
	return out
}

func linuxSysBlockHealth() []rmm.DiskHealthInventory {
	entries, err := filepath.Glob("/sys/block/*")
	if err != nil {
		return nil
	}
	out := make([]rmm.DiskHealthInventory, 0, len(entries))
	for _, path := range entries {
		name := filepath.Base(path)
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") {
			continue
		}
		if readFirstLine(filepath.Join(path, "removable")) == "1" {
			continue
		}
		out = append(out, rmm.DiskHealthInventory{
			Name:      name,
			Model:     readFirstLine(filepath.Join(path, "device/model")),
			Vendor:    readFirstLine(filepath.Join(path, "device/vendor")),
			Serial:    readFirstLine(filepath.Join(path, "device/serial")),
			SizeBytes: parseUint(readFirstLine(filepath.Join(path, "size"))) * 512,
			Status:    "present",
			Healthy:   true,
			Source:    "sysfs",
		})
	}
	return out
}

func zfsHealth() []rmm.ZFSHealthInventory {
	if !commandExists("zpool") {
		return nil
	}
	out, err := runPatchInventoryCommand("zpool", "list", "-H", "-o", "name,health,size,alloc,free,frag,cap")
	if err != nil {
		return nil
	}
	return parseZpoolList(out)
}

func unixMemoryHealth() rmm.MemoryHealthInventory {
	vm, err := mem.VirtualMemory()
	if err != nil {
		return rmm.MemoryHealthInventory{}
	}
	total, used := unixMemorySlots()
	return memoryInventory(vm.Total, vm.Used, vm.Available, vm.UsedPercent, total, used, "gopsutil")
}

func unixMemorySlots() (int, int) {
	if !commandExists("dmidecode") {
		return 0, 0
	}
	out, err := runPatchInventoryCommand("dmidecode", "-t", "memory")
	if err != nil {
		return 0, 0
	}
	return parseDmiMemorySlots(out)
}
