//go:build !windows

/*
Copyright 2026 AmidaWare Inc.

Licensed under the Tactical RMM License Version 1.0 (the “License”).
You may only use the Licensed Software in accordance with the License.
A copy of the License is available at:

https://license.tacticalrmm.com

*/

package agent

import "os"

func startupTaskIDs() []int {
	b, err := os.ReadFile("/etc/tacticalagent-startup-tasks")
	if err != nil {
		return nil
	}
	return parseTaskIDs(string(b))
}

// WatchLogons is Windows-only.
func (a *Agent) WatchLogons() {}
