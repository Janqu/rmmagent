/*
Copyright 2026 AmidaWare Inc.

Licensed under the Tactical RMM License Version 1.0 (the “License”).
You may only use the Licensed Software in accordance with the License.
A copy of the License is available at:

https://license.tacticalrmm.com

*/

package agent

import (
	"strconv"
	"strings"
)

// parseTaskIDs turns "12, 13;14" into []int, ignoring junk.
func parseTaskIDs(s string) []int {
	var ids []int
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		if id, err := strconv.Atoi(f); err == nil && id > 0 {
			ids = append(ids, id)
		}
	}
	return ids
}

// RunStartupTasks runs the automated tasks listed in the local startup list
// (Windows: HKLM\SOFTWARE\TacticalRMM\StartupTasks, other: /etc/tacticalagent-startup-tasks).
// Each task is fetched from the server like a scheduled task, so its result shows in the task history.
func (a *Agent) RunStartupTasks() {
	ids := startupTaskIDs()
	if len(ids) == 0 {
		return
	}
	a.Logger.Infof("Running startup tasks: %v", ids)
	for _, id := range ids {
		go func(id int) {
			if err := a.RunTask(id, true); err != nil {
				a.Logger.Errorf("startup task %d: %v", id, err)
			}
		}(id)
	}
}
