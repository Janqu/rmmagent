//go:build linux

package agent

import "testing"

func TestLinuxRemoteKeyAllowlist(t *testing.T) {
	for code, want := range map[string]string{
		"KeyA": "a", "Digit7": "7", "Enter": "Return", "ControlLeft": "Control_L",
	} {
		if got := linuxRemoteKey(code); got != want {
			t.Fatalf("linuxRemoteKey(%q) = %q, want %q", code, got, want)
		}
	}
	for _, code := range []string{"", "Key1", "DigitA", "--help", "XF86Launch0"} {
		if got := linuxRemoteKey(code); got != "" {
			t.Fatalf("unsafe key %q accepted as %q", code, got)
		}
	}
}

func TestLinuxShortcutAllowlist(t *testing.T) {
	if got := linuxShortcut("ctrl_c"); got != "ctrl+c" {
		t.Fatalf("ctrl_c = %q", got)
	}
	if got := linuxShortcut("ctrl_alt_delete"); got != "" {
		t.Fatalf("secure attention must not be synthesized: %q", got)
	}
}
