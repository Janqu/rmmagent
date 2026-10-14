//go:build !windows
// +build !windows

package agent

import "testing"

// Tests unixSystemdUnit used by ControlService for Mesh restart from TakeControl.
// User: continue Mesh clipboard / service control task.
func TestUnixSystemdUnit(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"mesh agent", "meshagent.service", true},
		{"meshagent", "meshagent.service", true},
		{"MeshAgent.service", "meshagent.service", true},
		{"tacticalrmm", "tacticalagent.service", true},
		{"tacticalagent", "tacticalagent.service", true},
		{"ssh", "ssh.service", true},
		{"bad name", "", false},
		{"../escape", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, err := unixSystemdUnit(tc.in)
		if tc.ok {
			if err != nil || got != tc.want {
				t.Fatalf("unixSystemdUnit(%q)=%q,%v want %q", tc.in, got, err, tc.want)
			}
			continue
		}
		if err == nil {
			t.Fatalf("unixSystemdUnit(%q) unexpectedly ok: %q", tc.in, got)
		}
	}
}

func TestUnixLaunchdLabel(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"mesh agent", "meshagent", true},
		{"meshagent", "meshagent", true},
		{"system/meshagent", "meshagent", true},
		{"tacticalagent", "tacticalagent", true},
		{"tacticalrmm", "tacticalagent", true},
		{"bad name", "", false},
		{"../escape", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, err := unixLaunchdLabel(tc.in)
		if tc.ok {
			if err != nil || got != tc.want {
				t.Fatalf("unixLaunchdLabel(%q)=%q,%v want %q", tc.in, got, err, tc.want)
			}
			continue
		}
		if err == nil {
			t.Fatalf("unixLaunchdLabel(%q) unexpectedly ok: %q", tc.in, got)
		}
	}
}
