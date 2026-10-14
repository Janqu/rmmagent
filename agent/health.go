package agent

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type AgentHealth struct {
	Version         string                     `json:"version"`
	AgentID         string                     `json:"agent_id"`
	AgentPK         int                        `json:"agent_pk"`
	Hostname        string                     `json:"hostname"`
	Platform        string                     `json:"platform"`
	GoArch          string                     `json:"goarch"`
	ProgramDir      string                     `json:"program_dir"`
	Executable      string                     `json:"executable"`
	MeshNodeID      string                     `json:"mesh_node_id,omitempty"`
	Mesh            MeshHealth                 `json:"mesh"`
	RemoteControl   RemoteControlHealth        `json:"remote_control"`
	NATS            AgentHealthNATS            `json:"nats"`
	Paths           map[string]AgentHealthPath `json:"paths"`
	Tools           map[string]AgentHealthTool `json:"tools"`
	Services        map[string]string          `json:"services,omitempty"`
	Hints           []string                   `json:"hints,omitempty"`
	RebootNeeded    bool                       `json:"reboot_needed"`
	InsecureTLS     bool                       `json:"insecure_tls"`
	ProxyConfigured bool                       `json:"proxy_configured"`
}

// MeshHealth is MeshAgent lifecycle/diagnostics owned by rmmagent (not KVM).
type MeshHealth struct {
	Path        string `json:"path,omitempty"`
	Exists      bool   `json:"exists"`
	SHA256      string `json:"sha256,omitempty"`
	ExpectedSHA string `json:"expected_sha256,omitempty"`
	Stale       bool   `json:"stale"`
	Service     string `json:"service,omitempty"`
	ServiceOK   bool   `json:"service_ok"`
	NodeID      string `json:"node_id,omitempty"`
	Session     string `json:"session,omitempty"`
	MeshVer     string `json:"mesh_ver,omitempty"`
}

type AgentHealthNATS struct {
	Server        string `json:"server"`
	ProxyPath     string `json:"proxy_path"`
	ProxyPort     string `json:"proxy_port"`
	PingInterval  int    `json:"ping_interval"`
	WSCompression bool   `json:"ws_compression"`
}

type AgentHealthPath struct {
	Path     string `json:"path"`
	Exists   bool   `json:"exists"`
	Writable bool   `json:"writable"`
}

type AgentHealthTool struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
}

func (a *Agent) Health() AgentHealth {
	rebootNeeded, _ := a.SystemRebootRequired()

	paths := map[string]AgentHealthPath{
		"program_dir": healthPath(a.ProgramDir),
		"tmp_dir":     healthPath(a.tmpDir()),
	}
	if a.WinRunAsUserTmpDir != "" {
		paths["run_as_user_tmp_dir"] = healthPath(a.WinRunAsUserTmpDir)
	}
	if a.MeshSystemEXE != "" {
		paths["mesh"] = healthPath(a.MeshSystemEXE)
	}

	services := map[string]string{}
	switch runtime.GOOS {
	case "windows":
		if status, err := GetServiceStatus(winSvcName); err == nil {
			services[winSvcName] = status
		}
		if status, err := GetServiceStatus(meshSvcName); err == nil {
			services[meshSvcName] = status
		}
	case "linux", "darwin":
		if status, err := GetServiceStatus("tacticalagent"); err == nil && status != "" {
			services["tacticalagent"] = status
		}
		if status, err := GetServiceStatus("meshagent"); err == nil && status != "" {
			services["meshagent"] = status
		}
	}
	if len(services) == 0 {
		services = nil
	}

	tools := map[string]AgentHealthTool{
		"python":  healthTool(a.PyBin),
		"nushell": healthTool(a.NuBin),
		"deno":    healthTool(a.DenoBin),
		"mesh":    healthTool(a.MeshSystemEXE),
	}
	if runtime.GOOS == "linux" {
		if path, err := exec.LookPath("wl-copy"); err == nil {
			tools["wl-clipboard"] = AgentHealthTool{Path: path, Exists: true}
		} else {
			tools["wl-clipboard"] = AgentHealthTool{Path: "wl-copy", Exists: false}
		}
	}

	hints := linuxMeshDesktopHints()
	if len(hints) == 0 {
		hints = nil
	}

	mesh := a.collectMeshHealth()
	nodeID := mesh.NodeID
	if nodeID == "" {
		nodeID = a.meshNodeIDQuick()
		mesh.NodeID = nodeID
	}

	return AgentHealth{
		Version:         a.Version,
		AgentID:         a.AgentID,
		AgentPK:         a.AgentPK,
		Hostname:        a.Hostname,
		Platform:        a.Platform,
		GoArch:          a.GoArch,
		ProgramDir:      a.ProgramDir,
		Executable:      a.EXE,
		MeshNodeID:      nodeID,
		Mesh:            mesh,
		RemoteControl:   a.remoteControlHealth(),
		RebootNeeded:    rebootNeeded,
		InsecureTLS:     a.Insecure,
		ProxyConfigured: a.Proxy != "",
		NATS: AgentHealthNATS{
			Server:        a.NatsServer,
			ProxyPath:     a.NatsProxyPath,
			ProxyPort:     a.NatsProxyPort,
			PingInterval:  a.NatsPingInterval,
			WSCompression: a.NatsWSCompression,
		},
		Paths:    paths,
		Tools:    tools,
		Services: services,
		Hints:    hints,
	}
}

func (a *Agent) collectMeshHealth() MeshHealth {
	mh := MeshHealth{
		Path:    a.MeshSystemEXE,
		Exists:  a.MeshSystemEXE != "" && pathExists(a.MeshSystemEXE),
		Session: linuxDisplaySession(),
		NodeID:  a.meshNodeIDQuick(),
	}
	svcName := a.meshServiceLookupName()
	if status, err := GetServiceStatus(svcName); err == nil {
		mh.Service = status
		mh.ServiceOK = meshServiceOK(status)
	}
	if mh.Exists {
		mh.SHA256 = a.localMeshSHA256()
	}
	if info, err := a.fetchExpectedMeshHash(); err == nil {
		mh.ExpectedSHA = info.SHA256
		mh.MeshVer = info.MeshVer
		compare := a.lastMeshInstallerSHA()
		if compare == "" {
			compare = mh.SHA256
		}
		mh.Stale = meshBinaryStale(compare, mh.ExpectedSHA)
	}
	return mh
}

// meshNodeIDQuick reads -nodeid once with a short timeout for health checks.
func (a *Agent) meshNodeIDQuick() string {
	if a.MeshSystemEXE == "" || !pathExists(a.MeshSystemEXE) {
		return ""
	}
	if runtime.GOOS == "windows" {
		out, err := CMD(a.MeshSystemEXE, []string{"-nodeid"}, 5, false)
		if err != nil {
			return ""
		}
		id := StripAll(out[0])
		if id == "" || strings.Contains(strings.ToLower(id), "not defined") {
			return ""
		}
		return id
	}
	opts := a.NewCMDOpts()
	opts.IsExecutable = true
	opts.Shell = a.MeshSystemEXE
	opts.Command = "-nodeid"
	opts.Timeout = 5
	out := a.CmdV2(opts)
	id := StripAll(out.Stdout)
	if id == "" || strings.Contains(strings.ToLower(id), "graphical version") || strings.Contains(strings.ToLower(id), "zenity") || strings.Contains(strings.ToLower(id), "error getting") {
		return ""
	}
	return id
}

func (a *Agent) tmpDir() string {
	if runtime.GOOS == "windows" {
		return a.WinTmpDir
	}
	return a.UnixTmpDir
}

func healthPath(path string) AgentHealthPath {
	return AgentHealthPath{
		Path:     path,
		Exists:   pathExists(path),
		Writable: dirWritable(path),
	}
}

func healthTool(path string) AgentHealthTool {
	return AgentHealthTool{
		Path:   path,
		Exists: pathExists(path),
	}
}

func pathExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func dirWritable(path string) bool {
	if path == "" {
		return false
	}

	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}

	f, err := os.CreateTemp(path, ".health-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}
