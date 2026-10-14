//go:build !windows && !linux

package agent

import "testing"

func TestUSBActionUnsupportedOnStubPlatform(t *testing.T) {
	a := &Agent{}
	if resp := a.USBAction("disable_all", "", "storage"); resp.Success {
		t.Fatal("expected the stub platform to refuse USB actions")
	}
}
