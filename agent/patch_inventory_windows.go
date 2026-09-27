//go:build windows

package agent

import (
	"time"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

func (a *Agent) PatchInventory() rmm.PatchInventory {
	inv := rmm.PatchInventory{
		AgentID:         a.AgentID,
		Platform:        a.Platform,
		Supported:       true,
		CheckedAt:       time.Now().UTC(),
		PackageManager:  "wua",
		PatchAllAllowed: true,
	}

	updates, err := WUAUpdates("IsInstalled=1 or IsInstalled=0 and Type='Software' and IsHidden=0")
	if err != nil {
		inv.Error = err.Error()
		return inv
	}
	for _, update := range updates {
		inv.Packages = append(inv.Packages, rmm.PatchPackage{
			Name:             update.Title,
			NeedsUpdate:      !update.Installed,
			IsSecurityUpdate: isSecurityUpdate(update),
			SourceRepository: "Windows Update",
		})
	}

	return inv
}
