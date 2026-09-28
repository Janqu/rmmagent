package agent

import (
	"strconv"
	"strings"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

func memoryInventory(total, used, free uint64, usedPct float64, slotsTotal, slotsUsed int, source string) rmm.MemoryHealthInventory {
	inv := rmm.MemoryHealthInventory{
		TotalBytes: total,
		UsedBytes:  used,
		FreeBytes:  free,
		UsedPct:    usedPct,
		SlotsTotal: slotsTotal,
		SlotsUsed:  slotsUsed,
		Source:     source,
	}
	if slotsTotal > 0 && slotsUsed >= 0 && slotsUsed <= slotsTotal {
		inv.SlotsFree = slotsTotal - slotsUsed
	}
	return inv
}

func parseZpoolList(output string) []rmm.ZFSHealthInventory {
	var pools []rmm.ZFSHealthInventory
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pool := rmm.ZFSHealthInventory{
			Name:    fields[0],
			Health:  fields[1],
			Healthy: strings.EqualFold(fields[1], "ONLINE"),
		}
		if len(fields) > 2 {
			pool.Size = fields[2]
		}
		if len(fields) > 3 {
			pool.Allocated = fields[3]
		}
		if len(fields) > 4 {
			pool.Free = fields[4]
		}
		if len(fields) > 5 {
			pool.Fragmentation = fields[5]
		}
		if len(fields) > 6 {
			pool.Capacity = fields[6]
		}
		pools = append(pools, pool)
	}
	return pools
}

func parseDmiMemorySlots(output string) (total int, used int) {
	inDevice := false
	deviceHasSize := false
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "Memory Device") {
			if inDevice {
				total++
				if deviceHasSize {
					used++
				}
			}
			inDevice = true
			deviceHasSize = false
			continue
		}
		if !inDevice || !strings.HasPrefix(line, "Size:") {
			continue
		}
		size := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "Size:")))
		if size != "" && !strings.Contains(size, "no module installed") && !strings.Contains(size, "not installed") {
			deviceHasSize = true
		}
	}
	if inDevice {
		total++
		if deviceHasSize {
			used++
		}
	}
	return total, used
}

func healthyPartition(usedPct float64) bool {
	return usedPct < 95
}

func parseUint(raw string) uint64 {
	value, _ := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	return value
}
