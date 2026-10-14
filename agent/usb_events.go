package agent

import (
	"runtime"
	"time"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

// usbMonitorInterval is the poll rate for USB connect/remove detection. It is
// the tuning knob between how fast a forbidden stick is blocked and how often
// the agent enumerates devices (a WMI query on Windows).
//
// On Windows a default-deny policy without allow rules also stops the USBSTOR
// class driver (applyUSBPolicy), so storage is blocked before it mounts and
// this poll only reports. Linux has no per-class kernel switch — writing
// authorized_default=0 would also de-authorize a keyboard plugged in later —
// so there a device stays usable until the next tick.
// ponytail: poll-based on Linux, up to one interval of exposure. Move to udev
// netlink events if that window has to close.
const usbMonitorInterval = 60 * time.Second

func usbControlSupported() bool {
	return runtime.GOOS == "windows" || runtime.GOOS == "linux"
}

// newUSBMonitorTicker returns nil on platforms without USB control, which
// tickerChan turns into a channel that never fires.
func newUSBMonitorTicker() *time.Ticker {
	if !usbControlSupported() {
		return nil
	}
	return time.NewTicker(usbMonitorInterval)
}

// MonitorUSB diffs the live device list against the previous poll, enforces
// the policy on devices that just appeared and reports what happened. The
// first call only seeds the snapshot; startup enforcement is done by
// EnforceUSBStoragePolicy.
func (a *Agent) MonitorUSB() {
	resp := a.ListUSBDevices()
	// A failed enumeration returns no devices; do not read that as unplugged.
	if resp.Devices == nil {
		if len(a.usbSnapshot) > 0 {
			return
		}
		resp.Devices = []rmm.USBDevice{}
	}
	events := diffUSBDevices(a.usbSnapshot, resp.Devices)
	a.usbSnapshot = resp.Devices
	a.enforceConnectedUSB(resp, events)
	a.ReportUSBEvents(events)
}

// enforceConnectedUSB disables devices that appeared but are not allowed by
// the policy, and rewrites their event as a block.
func (a *Agent) enforceConnectedUSB(resp rmm.USBListResp, events []rmm.USBEvent) {
	for i := range events {
		if events[i].Action != "connected" || events[i].Allowed {
			continue
		}
		device, ok := usbDeviceByInstanceID(resp.Devices, events[i].InstanceID)
		if !ok || !device.Enabled {
			continue
		}
		events[i].Action = "blocked"
		if result := a.USBAction("disable", device.InstanceID, "all"); !result.Success {
			events[i].ErrorMsg = result.ErrorMsg
			a.Logger.Errorln("MonitorUSB: blocking", device.InstanceID, result.ErrorMsg)
		}
	}
}

func usbDeviceByInstanceID(devices []rmm.USBDevice, instanceID string) (rmm.USBDevice, bool) {
	needle := normalizeUSBRule(instanceID)
	for _, device := range devices {
		if normalizeUSBRule(device.InstanceID) == needle {
			return device, true
		}
	}
	return rmm.USBDevice{}, false
}

// ReportUSBEvents posts USB connect/remove/block events to the RMM API.
func (a *Agent) ReportUSBEvents(events []rmm.USBEvent) {
	if len(events) == 0 || a.rClient == nil || a.AgentID == "" {
		return
	}
	payload := map[string]interface{}{"events": events}
	if _, err := a.rClient.R().SetBody(payload).Post("/api/v3/usbevents/"); err != nil {
		a.Logger.Debugln("ReportUSBEvents:", err)
	}
}
