//go:build !windows && !linux

package agent

import (
	"github.com/nats-io/nats.go"
	"io"
)

func remoteDesktopAvailable() bool { return false }
func startRemoteDesktop(_ *Agent, p map[string]string, _ *nats.Conn) map[string]interface{} {
	return map[string]interface{}{"status": "unsupported", "session_id": p["session_id"]}
}
func inputRemoteDesktop(map[string]string)              {}
func resizeRemoteDesktop(map[string]string)             {}
func displayRemoteDesktop(map[string]string)            {}
func shortcutRemoteDesktop(map[string]string)           {}
func clipboardGetRemoteDesktop(map[string]string)       {}
func clipboardSetRemoteDesktop(map[string]string)       {}
func stopRemoteDesktop(string)                          {}
func RunRemoteDesktopHelper(io.Reader, io.Writer) error { return nil }
