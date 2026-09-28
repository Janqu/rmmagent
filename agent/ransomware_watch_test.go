package agent

import (
	"os"
	"path/filepath"
	"testing"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

func TestCheckRansomwareCanary(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".qdt-rmm-canary.txt")
	first := checkRansomwareCanary(path)
	if !first.Healthy || first.Status != "created" {
		t.Fatalf("expected created healthy canary, got %+v", first)
	}
	second := checkRansomwareCanary(path)
	if !second.Healthy || second.Status != "ok" {
		t.Fatalf("expected ok canary, got %+v", second)
	}
	if err := os.WriteFile(path, []byte("changed"), 0644); err != nil {
		t.Fatal(err)
	}
	modified := checkRansomwareCanary(path)
	if modified.Healthy || modified.Status != "modified" {
		t.Fatalf("expected modified canary, got %+v", modified)
	}
}

func TestRansomwareScore(t *testing.T) {
	score := ransomwareScore([]rmm.RansomwareWatchFinding{
		{Severity: "critical"},
		{Severity: "high"},
		{Severity: "warning"},
	})
	if score != 95 {
		t.Fatalf("expected score 95, got %d", score)
	}
}

func TestRansomwareActions(t *testing.T) {
	quiet := ransomwareActions(rmm.RansomwareWatchReport{Score: 0})
	if len(quiet) != 1 || quiet[0] != "monitor" {
		t.Fatalf("unexpected quiet actions: %+v", quiet)
	}
	hot := ransomwareActions(rmm.RansomwareWatchReport{Suspicious: true, Score: 50})
	if len(hot) < 3 {
		t.Fatalf("expected containment recommendations, got %+v", hot)
	}
}
