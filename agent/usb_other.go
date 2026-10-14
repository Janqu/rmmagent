//go:build !windows && !linux

package agent

import rmm "github.com/Janqu/qdt-rmm-agent/shared"

func (a *Agent) ListUSBDevices() rmm.USBListResp {
	return rmm.USBListResp{Devices: []rmm.USBDevice{}}
}

func (a *Agent) USBAction(action, instanceID, scope string) rmm.WinSvcResp {
	return rmm.WinSvcResp{Success: false, ErrorMsg: "USB control is only supported on Windows and Linux agents"}
}

func (a *Agent) EnforceUSBStoragePolicy() {}
