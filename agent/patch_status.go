package agent

import (
	"strings"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

func addPatchStatusUpdate(status *rmm.PatchStatus, update rmm.WUAPackage) {
	if update.Installed {
		status.Installed++
		return
	}

	status.Missing++
	if update.Downloaded {
		status.Downloaded++
	}
	if update.Title != "" {
		status.MissingUpdates = append(status.MissingUpdates, update.Title)
	}

	switch strings.ToLower(update.Severity) {
	case "critical":
		status.Critical++
	case "important":
		status.Important++
	default:
		if isSecurityUpdate(update) {
			status.Security++
		} else {
			status.Other++
		}
	}
}

func isSecurityUpdate(update rmm.WUAPackage) bool {
	if strings.Contains(strings.ToLower(update.Title), "security") {
		return true
	}
	for _, category := range update.Categories {
		if strings.Contains(strings.ToLower(category), "security") {
			return true
		}
	}
	return false
}
