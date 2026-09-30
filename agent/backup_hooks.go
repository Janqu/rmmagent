package agent

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type BackupScript struct {
	ScriptID               int      `json:"script_id"`
	Name                   string   `json:"name"`
	Code                   string   `json:"code"`
	Shell                  string   `json:"shell"`
	Args                   []string `json:"args"`
	EnvVars                []string `json:"env_vars"`
	Timeout                int      `json:"timeout"`
	NushellEnableConfig    bool     `json:"nushell_enable_config"`
	DenoDefaultPermissions string   `json:"deno_default_permissions"`
}

type BackupHooks struct {
	Pre        *BackupScript `json:"pre"`
	Post       *BackupScript `json:"post"`
	PreFailure string        `json:"pre_failure"`
	PostWhen   string        `json:"post_when"`
}

type backupHookResult struct {
	Phase    string `json:"phase"`
	ScriptID int    `json:"script_id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	ExitCode int    `json:"exit_code"`
}

func (h *BackupHooks) validate() error {
	if h == nil {
		return nil
	}
	if (h.PreFailure != "abort" && h.PreFailure != "continue") || (h.PostWhen != "always" && h.PostWhen != "success") {
		return errors.New("invalid backup script policy")
	}
	for _, script := range []*BackupScript{h.Pre, h.Post} {
		if script == nil {
			continue
		}
		if script.ScriptID < 1 || script.Timeout < 1 || script.Timeout > 180 || len(script.Name) > 1000 || strings.TrimSpace(script.Code) == "" {
			return errors.New("invalid backup script or timeout")
		}
		if err := validateScriptPayload(script.Code, script.Args, script.EnvVars); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) runBackupWithHooks(ctx context.Context, job BackupJob, started time.Time) (backupStats, []backupHookResult, error) {
	stats := backupStats{}
	results := []backupHookResult{}
	if err := job.Hooks.validate(); err != nil {
		return stats, results, err
	}
	if job.Hooks == nil || (job.Hooks.Pre == nil && job.Hooks.Post == nil) {
		stats, err := a.runBackup(ctx, job, started)
		return stats, results, err
	}
	run := func(phase string, script *BackupScript, state string) bool {
		result := backupHookResult{Phase: phase, ScriptID: script.ScriptID, Name: script.Name, Status: "running"}
		results = append(results, result)
		body := stats.status(job.ID, "running", "", 0)
		body["hook_results"] = results
		a.backupStatus(job.Endpoint, body)
		env := append([]string{}, script.EnvVars...)
		env = append(env, "QDT_BACKUP_RUN_ID="+strconv.Itoa(job.ID), "QDT_BACKUP_PROFILE_ID="+strconv.Itoa(job.ProfileID), "QDT_BACKUP_PHASE="+phase, "QDT_BACKUP_STATUS="+state)
		// Reuse the RMM executor and its bounded timeout. Cancellation waits for
		// an active hook (at most 180s); the post-hook can still undo preparation.
		_, _, code, err := a.RunScript(script.Code, script.Shell, append([]string{}, script.Args...), script.Timeout, false, env, script.NushellEnableConfig, script.DenoDefaultPermissions)
		result.ExitCode, result.Status = code, "success"
		if err != nil || code != 0 {
			result.Status = "failed"
			if code == 0 {
				result.ExitCode = 1
			}
		}
		results[len(results)-1] = result
		body["hook_results"] = results
		a.backupStatus(job.Endpoint, body)
		return result.Status == "success"
	}
	var err error
	if ctx.Err() != nil {
		return stats, results, ctx.Err()
	}
	if pre := job.Hooks.Pre; pre != nil && !run("pre", pre, "pending") && job.Hooks.PreFailure == "abort" {
		err = errors.New("Vor-Skript fehlgeschlagen; Backup wurde nicht ausgeführt.")
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err == nil {
		stats, err = a.runBackup(ctx, job, started)
	}
	state := "success"
	if err != nil {
		state = "failed"
	}
	if errors.Is(err, context.Canceled) {
		state = "canceled"
	}
	if post := job.Hooks.Post; post != nil {
		if job.Hooks.PostWhen == "always" || err == nil {
			run("post", post, state)
		} else {
			results = append(results, backupHookResult{Phase: "post", ScriptID: post.ScriptID, Name: post.Name, Status: "skipped"})
		}
	}
	return stats, results, err
}

func backupHookWarning(results []backupHookResult) string {
	for _, r := range results {
		if r.Status == "failed" {
			return fmt.Sprintf("Skriptwarnung: %s-Skript (ID %d), Exitcode %d. Sicherungsdaten separat prüfen.", r.Phase, r.ScriptID, r.ExitCode)
		}
	}
	return ""
}
