package agent

import rmm "github.com/Janqu/qdt-rmm-agent/shared"

func recoverTacticalAgent(control func(string, string) rmm.WinSvcResp) string {
	result := control(winSvcName, "restart")
	if result.Success {
		return "ok"
	}
	if result.ErrorMsg == "" {
		return "tacagent recovery failed"
	}
	return result.ErrorMsg
}
