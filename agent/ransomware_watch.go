package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
	gops "github.com/shirou/gopsutil/v3/process"
)

const canaryContent = "qdt-rmm ransomware canary v1\n"

var ransomwareProcessNeedles = []string{
	"vssadmin delete shadows",
	"wmic shadowcopy delete",
	"wbadmin delete catalog",
	"bcdedit /set",
	"delete shadows",
	"cipher /w",
	"wevtutil cl",
	"fsutil usn deletejournal",
	"recoveryenabled no",
	"ignoreallfailures",
}

var ransomwareNameNeedles = []string{
	"wannacry",
	"lockbit",
	"conti",
	"ryuk",
	"blackcat",
	"alphv",
	"clop",
	"revil",
	"darkside",
}

func (a *Agent) RansomwareWatch() rmm.RansomwareWatchReport {
	report := rmm.RansomwareWatchReport{
		AgentID:         a.AgentID,
		Platform:        a.Platform,
		CheckedAt:       time.Now().UTC(),
		WazuhCompatible: true,
	}
	report.Canaries = a.checkRansomwareCanaries()
	report.Findings = append(report.Findings, ransomwareCanaryFindings(report.Canaries)...)
	report.Findings = append(report.Findings, suspiciousProcessFindings()...)
	report.Score = ransomwareScore(report.Findings)
	report.Suspicious = report.Score >= 50
	report.RecommendedActions = ransomwareActions(report)
	return report
}

func (a *Agent) checkRansomwareCanaries() []rmm.RansomwareCanaryStatus {
	var statuses []rmm.RansomwareCanaryStatus
	for _, dir := range a.ransomwareCanaryDirs() {
		path := filepath.Join(dir, ".qdt-rmm-canary.txt")
		statuses = append(statuses, checkRansomwareCanary(path))
	}
	return statuses
}

func (a *Agent) ransomwareCanaryDirs() []string {
	dirs := []string{a.tmpDir(), os.TempDir()}
	if a.ProgramDir != "" {
		dirs = append(dirs, a.ProgramDir)
	}
	if runtime.GOOS != "windows" {
		dirs = append(dirs, "/var/tmp")
	}
	var clean []string
	for _, dir := range dirs {
		dir = strings.TrimSpace(dir)
		if dir != "" && filepath.IsAbs(dir) {
			clean = append(clean, dir)
		}
	}
	if len(clean) == 0 {
		clean = append(clean, os.TempDir())
	}
	return dedupeStrings(clean)
}

func checkRansomwareCanary(path string) rmm.RansomwareCanaryStatus {
	status := rmm.RansomwareCanaryStatus{Path: path}
	expected := canaryHash()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if mkErr := os.MkdirAll(filepath.Dir(path), 0755); mkErr != nil {
			status.Status = "error"
			status.Error = mkErr.Error()
			return status
		}
		if writeErr := os.WriteFile(path, []byte(canaryContent), 0644); writeErr != nil {
			status.Status = "error"
			status.Error = writeErr.Error()
			return status
		}
		status.Status = "created"
		status.Healthy = true
		return status
	}
	if err != nil {
		status.Status = "error"
		status.Error = err.Error()
		return status
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != expected {
		status.Status = "modified"
		return status
	}
	status.Status = "ok"
	status.Healthy = true
	return status
}

func canaryHash() string {
	sum := sha256.Sum256([]byte(canaryContent))
	return hex.EncodeToString(sum[:])
}

func ransomwareCanaryFindings(canaries []rmm.RansomwareCanaryStatus) []rmm.RansomwareWatchFinding {
	var findings []rmm.RansomwareWatchFinding
	for _, canary := range canaries {
		switch canary.Status {
		case "modified":
			findings = append(findings, rmm.RansomwareWatchFinding{
				Category: "canary",
				Severity: "critical",
				Title:    "Ransomware canary was modified",
				Detail:   canary.Path,
			})
		case "error":
			findings = append(findings, rmm.RansomwareWatchFinding{
				Category: "canary",
				Severity: "warning",
				Title:    "Ransomware canary could not be checked",
				Detail:   canary.Path + ": " + canary.Error,
			})
		}
	}
	return findings
}

func suspiciousProcessFindings() []rmm.RansomwareWatchFinding {
	procs, err := gops.Processes()
	if err != nil {
		return nil
	}
	var findings []rmm.RansomwareWatchFinding
	for _, proc := range procs {
		name, _ := proc.Name()
		cmdline, _ := proc.Cmdline()
		text := strings.ToLower(strings.TrimSpace(name + " " + cmdline))
		if text == "" {
			continue
		}
		for _, needle := range ransomwareNameNeedles {
			if strings.Contains(text, needle) {
				findings = append(findings, rmm.RansomwareWatchFinding{
					Category: "process",
					Severity: "critical",
					Title:    "Known ransomware process name matched",
					Detail:   needle,
					PID:      proc.Pid,
					Process:  name,
				})
				break
			}
		}
		for _, needle := range ransomwareProcessNeedles {
			if strings.Contains(text, needle) {
				findings = append(findings, rmm.RansomwareWatchFinding{
					Category: "process",
					Severity: "high",
					Title:    "Suspicious destructive command matched",
					Detail:   needle,
					PID:      proc.Pid,
					Process:  name,
				})
				break
			}
		}
	}
	return findings
}

func ransomwareScore(findings []rmm.RansomwareWatchFinding) int {
	score := 0
	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			score += 50
		case "high":
			score += 35
		case "warning":
			score += 10
		}
	}
	if score > 100 {
		return 100
	}
	return score
}

func ransomwareActions(report rmm.RansomwareWatchReport) []string {
	if !report.Suspicious {
		return []string{"monitor"}
	}
	return []string{
		"alert_rmm",
		"collect_process_snapshot",
		"consider_network_isolation",
		"verify_backup_status",
	}
}
