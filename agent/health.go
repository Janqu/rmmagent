package agent

import (
	"os"
	"runtime"
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
	NATS            AgentHealthNATS            `json:"nats"`
	Paths           map[string]AgentHealthPath `json:"paths"`
	Tools           map[string]AgentHealthTool `json:"tools"`
	Services        map[string]string          `json:"services,omitempty"`
	RebootNeeded    bool                       `json:"reboot_needed"`
	InsecureTLS     bool                       `json:"insecure_tls"`
	ProxyConfigured bool                       `json:"proxy_configured"`
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
	if runtime.GOOS == "windows" {
		if status, err := GetServiceStatus(winSvcName); err == nil {
			services[winSvcName] = status
		}
		if status, err := GetServiceStatus(meshSvcName); err == nil {
			services[meshSvcName] = status
		}
	}
	if len(services) == 0 {
		services = nil
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
		Paths: paths,
		Tools: map[string]AgentHealthTool{
			"python":  healthTool(a.PyBin),
			"nushell": healthTool(a.NuBin),
			"deno":    healthTool(a.DenoBin),
			"mesh":    healthTool(a.MeshSystemEXE),
		},
		Services: services,
	}
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
