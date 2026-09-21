/*
Copyright 2026 AmidaWare Inc.

Licensed under the Tactical RMM License Version 1.0 (the “License”).
You may only use the Licensed Software in accordance with the License.
A copy of the License is available at:

https://license.tacticalrmm.com

*/

package agent

import "golang.org/x/sys/windows/registry"

func startupTaskIDs() []int {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\TacticalRMM`, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	s, _, err := k.GetStringValue("StartupTasks")
	if err != nil {
		return nil
	}
	return parseTaskIDs(s)
}
