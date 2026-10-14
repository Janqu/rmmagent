//go:build !linux
// +build !linux

package agent

// linuxMeshDesktopHints is a no-op outside Linux.
// Callers: Health() in health.go. User: "weiter" (P3).
func linuxMeshDesktopHints() []string { return nil }

// linuxDisplaySession is Linux-only; empty on Windows/Darwin.
// Callers: collectMeshHealth() in health.go.
func linuxDisplaySession() string { return "" }
