//go:build fyne

package main

import (
	"strings"
	"testing"
)

func TestInstallerInfoText(t *testing.T) {
	got := installerInfoText(installerTokenInfo{Site: 4, MonitoringType: "workstation", RDP: true, Ping: true})
	for _, want := range []string{"site 4", "workstation", "rdp", "ping"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q missing %q", got, want)
		}
	}
}
