package agent

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestDirWritable(t *testing.T) {
	if !dirWritable(t.TempDir()) {
		t.Fatal("temp dir should be writable")
	}
	if dirWritable(filepath.Join(t.TempDir(), "missing")) {
		t.Fatal("missing dir should not be writable")
	}
}

func TestHealthIncludesRemoteControl(t *testing.T) {
	a := &Agent{AgentID: "agent-test", NatsServer: "wss://rmm.example.test/ws"}
	health := a.Health()
	if health.RemoteControl.Available != remoteDesktopAvailable() || health.RemoteControl.Transport != "nats" || health.RemoteControl.Fallback != "" {
		t.Fatalf("remote control health missing: %#v", health.RemoteControl)
	}
	for _, capability := range []string{"desktop_frames", "desktop_input"} {
		if !slices.Contains(health.RemoteControl.Capabilities, capability) {
			t.Fatalf("remote control capability %q missing: %#v", capability, health.RemoteControl)
		}
	}
}
