//go:build linux
// +build linux

package agent

import "testing"

// Callers: go test ./agent (linux). Covers linuxDisplaySession used by MeshHealth.
// User: "weiter ausbauen und mehr aus dem MeshAgent in der RMM agent übernehmen"
func TestLinuxDisplaySessionEnv(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("DISPLAY", "")
	t.Setenv("XDG_SESSION_TYPE", "")

	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	if got := linuxDisplaySession(); got != "wayland" {
		t.Fatalf("WAYLAND_DISPLAY → %q", got)
	}

	t.Setenv("WAYLAND_DISPLAY", "")
	t.Setenv("XDG_SESSION_TYPE", "x11")
	if got := linuxDisplaySession(); got != "x11" {
		t.Fatalf("XDG_SESSION_TYPE=x11 → %q", got)
	}

	t.Setenv("XDG_SESSION_TYPE", "wayland")
	if got := linuxDisplaySession(); got != "wayland" {
		t.Fatalf("XDG_SESSION_TYPE=wayland → %q", got)
	}
}
