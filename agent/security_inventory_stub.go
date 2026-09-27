//go:build !windows

package agent

import rmm "github.com/Janqu/qdt-rmm-agent/shared"

func (a *Agent) SecurityInventory() []rmm.SecurityProductInventory {
	return []rmm.SecurityProductInventory{}
}
