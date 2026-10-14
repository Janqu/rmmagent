package agent

import (
	"testing"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

func TestRecoverTacticalAgent(t *testing.T) {
	var name, action string
	got := recoverTacticalAgent(func(n, a string) rmm.WinSvcResp {
		name, action = n, a
		return rmm.WinSvcResp{Success: true}
	})
	if got != "ok" || name != winSvcName || action != "restart" {
		t.Fatalf("success: %q %s %s", got, name, action)
	}
	got = recoverTacticalAgent(func(string, string) rmm.WinSvcResp {
		return rmm.WinSvcResp{ErrorMsg: "denied"}
	})
	if got != "denied" {
		t.Fatalf("failure: %q", got)
	}
	got = recoverTacticalAgent(func(string, string) rmm.WinSvcResp {
		return rmm.WinSvcResp{}
	})
	if got != "tacagent recovery failed" {
		t.Fatalf("empty failure: %q", got)
	}
}
