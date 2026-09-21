/*
Copyright 2026 AmidaWare Inc.

Licensed under the Tactical RMM License Version 1.0 (the “License”).
You may only use the Licensed Software in accordance with the License.
A copy of the License is available at:

https://license.tacticalrmm.com

*/

package agent

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func startupTaskIDs() []int { return regTaskIDs("StartupTasks") }
func logonTaskIDs() []int   { return regTaskIDs("LogonTasks") }

func regTaskIDs(name string) []int {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\TacticalRMM`, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	s, _, err := k.GetStringValue(name)
	if err != nil {
		return nil
	}
	return parseTaskIDs(s)
}

// activeSessions returns the IDs of interactive sessions (console/RDP) that are currently active.
func activeSessions() map[uint32]bool {
	var info *windows.WTS_SESSION_INFO
	var n uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &info, &n); err != nil {
		return nil
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	out := map[uint32]bool{}
	for _, s := range unsafe.Slice(info, n) {
		if s.SessionID != 0 && s.State == windows.WTSActive {
			out[s.SessionID] = true
		}
	}
	return out
}

// WatchLogons runs the LogonTasks whenever a session becomes active (logon, RDP connect, reconnect).
// Sessions already active when the agent starts do not trigger; StartupTasks covers boot.
func (a *Agent) WatchLogons() {
	if len(logonTaskIDs()) == 0 {
		return
	}
	seen := activeSessions()
	for range time.Tick(10 * time.Second) {
		cur := activeSessions()
		if cur == nil {
			continue
		}
		fresh := false
		for id := range cur {
			if !seen[id] {
				fresh = true
			}
		}
		seen = cur
		if fresh {
			time.Sleep(5 * time.Second) // let the user session finish loading for run-as-user tasks
			a.runTaskIDs("logon", logonTaskIDs(), false)
		}
	}
}
