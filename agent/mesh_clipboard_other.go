//go:build !linux
// +build !linux

package agent

// ensureMeshClipboardTools is a no-op outside Linux.
// Callers: reinstallMeshNix, Install. User: Zwischenablage-Probleme lösen.
func (a *Agent) ensureMeshClipboardTools() {}
