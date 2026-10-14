package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// meshReconcileReinstallMinInterval caps automatic RecoverMesh from the watchdog
// so a bad cache/hash cannot loop reinstalls. Manual recovermesh RPC is unlimited.
const meshReconcileReinstallMinInterval = time.Hour

type meshReconcileAction string

const (
	meshActionNone         meshReconcileAction = ""
	meshActionStartService meshReconcileAction = "start_service"
	meshActionReinstall    meshReconcileAction = "reinstall"
)

type meshHashInfo struct {
	SHA256  string `json:"sha256"`
	MeshVer string `json:"mesh_ver"`
	Plat    string `json:"plat"`
	Goarch  string `json:"goarch"`
}

// meshServiceOK reports whether a platform service status means Mesh is up.
func meshServiceOK(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running", "active":
		return true
	default:
		return false
	}
}

// meshReconcilePlan decides the next Mesh orchestration step.
// Empty serviceStatus means "unknown" — do not start/stop blindly.
func meshReconcilePlan(exists bool, serviceStatus string, stale bool) meshReconcileAction {
	if !exists {
		return meshActionReinstall
	}
	if stale {
		return meshActionReinstall
	}
	status := strings.ToLower(strings.TrimSpace(serviceStatus))
	if status == "" || meshServiceOK(status) {
		return meshActionNone
	}
	switch status {
	case "start_pending", "stop_pending", "continue_pending",
		"activating", "deactivating", "reloading":
		return meshActionNone
	}
	return meshActionStartService
}

func (a *Agent) meshServiceLookupName() string {
	switch runtime.GOOS {
	case "windows":
		return meshSvcName
	case "linux", "darwin":
		return "meshagent"
	default:
		return a.MeshSVC
	}
}

// fetchExpectedMeshHash asks the RMM for the current Mesh installer digest
// (server-side cache / MeshCentral download) without transferring the binary.
func (a *Agent) fetchExpectedMeshHash() (meshHashInfo, error) {
	var info meshHashInfo
	if a.rClient == nil || a.AgentID == "" {
		return info, fmt.Errorf("agent client not configured")
	}
	url := fmt.Sprintf("/api/v3/%s/meshhash/", a.AgentID)
	r, err := a.rClient.R().SetResult(&info).Get(url)
	if err != nil {
		return info, err
	}
	if r.IsError() {
		return info, fmt.Errorf("meshhash status %d", r.StatusCode())
	}
	if info.SHA256 == "" {
		info.SHA256 = strings.TrimSpace(strings.ToLower(r.Header().Get("X-Mesh-Agent-SHA256")))
	} else {
		info.SHA256 = strings.TrimSpace(strings.ToLower(info.SHA256))
	}
	if info.SHA256 == "" {
		return info, fmt.Errorf("meshhash empty")
	}
	return info, nil
}

// localMeshSHA256 returns the hex digest of the installed Mesh binary, or "".
func (a *Agent) localMeshSHA256() string {
	if a.MeshSystemEXE == "" || !pathExists(a.MeshSystemEXE) {
		return ""
	}
	sum, err := fileSHA256(a.MeshSystemEXE)
	if err != nil {
		a.Logger.Debugln("localMeshSHA256:", err)
		return ""
	}
	return sum
}

// meshInstallerHashPath stores the SHA-256 of the last Mesh *installer* we
// downloaded. The installed MeshAgent.exe often differs from that installer
// (Windows), so stale detection must not compare binary≠installer digests.
func (a *Agent) meshInstallerHashPath() string {
	if a.MeshSystemEXE != "" {
		return filepath.Join(filepath.Dir(a.MeshSystemEXE), "mesh.installer.sha256")
	}
	switch runtime.GOOS {
	case "windows":
		if a.ProgramDir != "" {
			return filepath.Join(a.ProgramDir, "mesh.installer.sha256")
		}
	default:
		return filepath.Join(nixMeshDir, "mesh.installer.sha256")
	}
	return ""
}

func (a *Agent) rememberMeshInstallerSHA(sum string) {
	sum = strings.TrimSpace(strings.ToLower(sum))
	path := a.meshInstallerHashPath()
	if sum == "" || path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	if err := os.WriteFile(path, []byte(sum+"\n"), 0644); err != nil {
		a.Logger.Debugln("rememberMeshInstallerSHA:", err)
	}
}

func (a *Agent) lastMeshInstallerSHA() string {
	path := a.meshInstallerHashPath()
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ToLower(string(b)))
}

// meshBinaryStale is true when both digests are known and differ.
// Prefer last-installed installer hash vs server expected; fall back to local
// binary only when no sidecar exists (legacy installs).
func meshBinaryStale(installedOrLocal, expected string) bool {
	installedOrLocal = strings.TrimSpace(strings.ToLower(installedOrLocal))
	expected = strings.TrimSpace(strings.ToLower(expected))
	return installedOrLocal != "" && expected != "" && installedOrLocal != expected
}

func (a *Agent) allowMeshReinstall() bool {
	a.meshReconcileMu.Lock()
	defer a.meshReconcileMu.Unlock()
	if !a.meshLastReinstall.IsZero() && time.Since(a.meshLastReinstall) < meshReconcileReinstallMinInterval {
		return false
	}
	a.meshLastReinstall = time.Now()
	return true
}

// ReportMeshHealth posts MeshAgent lifecycle diagnostics to the RMM API.
func (a *Agent) ReportMeshHealth() {
	if a.rClient == nil || a.AgentID == "" {
		return
	}
	mh := a.collectMeshHealth()
	payload := map[string]interface{}{
		"exists":     mh.Exists,
		"stale":      mh.Stale,
		"service_ok": mh.ServiceOK,
	}
	if mh.Path != "" {
		payload["path"] = mh.Path
	}
	if mh.SHA256 != "" {
		payload["sha256"] = mh.SHA256
	}
	if mh.ExpectedSHA != "" {
		payload["expected_sha256"] = mh.ExpectedSHA
	}
	if mh.Service != "" {
		payload["service"] = mh.Service
	}
	if mh.NodeID != "" {
		payload["node_id"] = mh.NodeID
	}
	if mh.Session != "" {
		payload["session"] = mh.Session
	}
	if mh.MeshVer != "" {
		payload["mesh_ver"] = mh.MeshVer
	}
	_, err := a.rClient.R().SetBody(payload).Post("/api/v3/meshhealth/")
	if err != nil {
		a.Logger.Debugln("ReportMeshHealth:", err)
	}
}

// meshHealthCheckin returns a local-only Mesh snapshot for NATS agentinfo
// (no meshhash HTTP round-trip).
func (a *Agent) meshHealthCheckin() map[string]interface{} {
	mh := MeshHealth{
		Exists:  a.MeshSystemEXE != "" && pathExists(a.MeshSystemEXE),
		Session: linuxDisplaySession(),
		NodeID:  a.meshNodeIDQuick(),
	}
	svcName := a.meshServiceLookupName()
	if status, err := GetServiceStatus(svcName); err == nil {
		mh.Service = status
		mh.ServiceOK = meshServiceOK(status)
	}
	out := map[string]interface{}{
		"exists":     mh.Exists,
		"service_ok": mh.ServiceOK,
		"stale":      false,
	}
	if mh.Service != "" {
		out["service"] = mh.Service
	}
	if mh.NodeID != "" {
		out["node_id"] = mh.NodeID
	}
	if mh.Session != "" {
		out["session"] = mh.Session
	}
	return out
}

// ReconcileMesh keeps Mesh installed and running without owning KVM capture.
// Missing/stale binary → rate-limited RecoverMesh; stopped service → start.
func (a *Agent) ReconcileMesh() {
	if a.MeshSystemEXE == "" {
		return
	}
	exists := pathExists(a.MeshSystemEXE)
	svcName := a.meshServiceLookupName()
	status, _ := GetServiceStatus(svcName)

	expected := ""
	if info, err := a.fetchExpectedMeshHash(); err == nil {
		expected = info.SHA256
	} else {
		a.Logger.Debugln("ReconcileMesh() meshhash:", err)
	}
	// Prefer installer sidecar (correct on Windows); fall back to binary hash.
	installed := a.lastMeshInstallerSHA()
	if installed == "" && exists {
		installed = a.localMeshSHA256()
	}
	stale := meshBinaryStale(installed, expected)
	action := meshReconcilePlan(exists, status, stale)
	a.Logger.Debugf("ReconcileMesh: exists=%v status=%q stale=%v action=%q", exists, status, stale, action)

	switch action {
	case meshActionStartService:
		a.Logger.Infoln("ReconcileMesh: starting mesh service", svcName)
		ret := a.ControlService(svcName, "start")
		if !ret.Success {
			a.Logger.Errorln("ReconcileMesh: start failed:", ret.ErrorMsg)
		}
	case meshActionReinstall:
		if !a.allowMeshReinstall() {
			a.Logger.Debugln("ReconcileMesh: reinstall skipped (rate limit)")
			return
		}
		reason := "missing"
		if stale {
			reason = "stale binary"
		}
		a.Logger.Infoln("ReconcileMesh: recovering mesh (" + reason + ")")
		a.RecoverMesh()
	}
}
