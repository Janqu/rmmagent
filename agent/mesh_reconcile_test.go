package agent

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestMeshReconcilePlan(t *testing.T) {
	cases := []struct {
		name   string
		exists bool
		status string
		stale  bool
		want   meshReconcileAction
	}{
		{"missing binary", false, "", false, meshActionReinstall},
		{"missing even if active", false, "active", false, meshActionReinstall},
		{"stale binary", true, "active", true, meshActionReinstall},
		{"stale overrides stop", true, "stopped", true, meshActionReinstall},
		{"healthy linux", true, "active", false, meshActionNone},
		{"healthy windows", true, "running", false, meshActionNone},
		{"unknown status", true, "", false, meshActionNone},
		{"stopped", true, "stopped", false, meshActionStartService},
		{"inactive", true, "inactive", false, meshActionStartService},
		{"failed", true, "failed", false, meshActionStartService},
		{"start pending", true, "start_pending", false, meshActionNone},
		{"activating", true, "activating", false, meshActionNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := meshReconcilePlan(tc.exists, tc.status, tc.stale); got != tc.want {
				t.Fatalf("meshReconcilePlan(%v,%q,%v)=%q want %q", tc.exists, tc.status, tc.stale, got, tc.want)
			}
		})
	}
}

func TestMeshBinaryStale(t *testing.T) {
	if meshBinaryStale("", "abc") {
		t.Fatal("empty local should not be stale")
	}
	if meshBinaryStale("abc", "") {
		t.Fatal("empty expected should not be stale")
	}
	if meshBinaryStale("abc", "abc") {
		t.Fatal("matching digests should not be stale")
	}
	if !meshBinaryStale("abc", "def") {
		t.Fatal("mismatch should be stale")
	}
	if meshBinaryStale("ABC", "abc") {
		t.Fatal("case-normalized match should not be stale")
	}
}

func TestMeshServiceOK(t *testing.T) {
	if !meshServiceOK("active") || !meshServiceOK("Running") {
		t.Fatal("active/running should be ok")
	}
	if meshServiceOK("stopped") || meshServiceOK("") {
		t.Fatal("stopped/empty should not be ok")
	}
}

func TestRememberMeshInstallerSHA(t *testing.T) {
	dir := t.TempDir()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	a := &Agent{
		MeshSystemEXE: filepath.Join(dir, "meshagent"),
		Logger:        logger,
	}
	a.rememberMeshInstallerSHA("  AbCdEf  ")
	if got := a.lastMeshInstallerSHA(); got != "abcdef" {
		t.Fatalf("lastMeshInstallerSHA=%q want abcdef", got)
	}
	if meshBinaryStale(a.lastMeshInstallerSHA(), "abcdef") {
		t.Fatal("matching installer sidecar should not be stale")
	}
	if !meshBinaryStale(a.lastMeshInstallerSHA(), "ffffff") {
		t.Fatal("mismatched expected should be stale")
	}
}
