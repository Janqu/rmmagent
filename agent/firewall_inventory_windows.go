//go:build windows

package agent

import rmm "github.com/Janqu/qdt-rmm-agent/shared"

func collectFirewallInventory(appliance string) *rmm.FirewallInventory {
	return &rmm.FirewallInventory{Detected: appliance != "", Appliance: appliance}
}

func (a *Agent) FirewallInventory() *rmm.FirewallInventory {
	return &rmm.FirewallInventory{}
}
