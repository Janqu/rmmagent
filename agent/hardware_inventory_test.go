package agent

import "testing"

func TestParseZpoolList(t *testing.T) {
	pools := parseZpoolList("tank\tONLINE\t1T\t200G\t800G\t3%\t20%\nbackup\tDEGRADED\t2T\t1T\t1T\t10%\t50%")
	if len(pools) != 2 {
		t.Fatalf("expected 2 pools, got %d", len(pools))
	}
	if !pools[0].Healthy || pools[1].Healthy {
		t.Fatalf("unexpected health flags: %+v", pools)
	}
	if pools[0].Capacity != "20%" || pools[1].Health != "DEGRADED" {
		t.Fatalf("unexpected pool parse: %+v", pools)
	}
}

func TestParseDmiMemorySlots(t *testing.T) {
	total, used := parseDmiMemorySlots(`
Memory Device
	Size: 16384 MB
	Locator: DIMM_A1
Memory Device
	Size: No Module Installed
	Locator: DIMM_A2
Memory Device
	Size: 8192 MB
	Locator: DIMM_B1
`)
	if total != 3 || used != 2 {
		t.Fatalf("expected 3 total / 2 used, got %d / %d", total, used)
	}
}

func TestHealthyPartition(t *testing.T) {
	if !healthyPartition(94.9) {
		t.Fatal("94.9 should be healthy")
	}
	if healthyPartition(95) {
		t.Fatal("95 should be unhealthy")
	}
}
