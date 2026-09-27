package agent

import (
	"testing"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

func TestAddPatchStatusUpdate(t *testing.T) {
	status := rmm.PatchStatus{}

	addPatchStatusUpdate(&status, rmm.WUAPackage{Installed: true})
	addPatchStatusUpdate(&status, rmm.WUAPackage{
		Title:      "Security Update",
		Downloaded: true,
		Severity:   "Critical",
	})
	addPatchStatusUpdate(&status, rmm.WUAPackage{
		Title:      "Definition Update",
		Categories: []string{"Security Updates"},
	})

	if status.Installed != 1 || status.Missing != 2 || status.Downloaded != 1 {
		t.Fatalf("unexpected totals: %+v", status)
	}
	if status.Critical != 1 || status.Security != 1 || status.Other != 0 {
		t.Fatalf("unexpected risk buckets: %+v", status)
	}
	if len(status.MissingUpdates) != 2 {
		t.Fatalf("unexpected missing update titles: %+v", status.MissingUpdates)
	}
}
