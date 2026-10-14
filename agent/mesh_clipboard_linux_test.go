//go:build linux
// +build linux

package agent

import (
	"strings"
	"testing"
)

// Tests meshClipboardInstallCommand used by ensureMeshClipboardTools.
// User: "Kannst du die Zwischenablagen Probleme noch lösen ?"
func TestMeshClipboardInstallCommand(t *testing.T) {
	cmd, env := meshClipboardInstallCommand([]string{"wl-clipboard", "xclip"})
	if cmd != "" {
		if !strings.Contains(cmd, "wl-clipboard") || !strings.Contains(cmd, "xclip") {
			t.Fatalf("unexpected install command %q", cmd)
		}
		if detectUnixPatchManager() == "apt" {
			if len(env) != 1 || env[0] != "DEBIAN_FRONTEND=noninteractive" {
				t.Fatalf("apt env %v", env)
			}
		}
	}
	cmd, _ = meshClipboardInstallCommand([]string{"wl-clipboard"})
	if cmd != "" && strings.Contains(cmd, "xclip") {
		t.Fatalf("should not install unrequested xclip: %q", cmd)
	}
}
