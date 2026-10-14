//go:build linux
// +build linux

package agent

import (
	"fmt"
	"os/exec"
	"strings"
)

// ensureMeshClipboardTools installs wl-clipboard (Wayland) and xclip (X11) when
// missing. MeshAgent clipboard.js uses wl-copy/wl-paste under Wayland and xclip
// under X11; without them remote clipboard fails.
// Callers: reinstallMeshNix (agent_unix.go), Install linux path (install.go).
// User instruction: "Kannst du die Zwischenablagen Probleme noch lösen ?"
func (a *Agent) ensureMeshClipboardTools() {
	needWL := !commandExists("wl-copy") || !commandExists("wl-paste")
	needXclip := !commandExists("xclip")
	if !needWL && !needXclip {
		a.Logger.Debugln("Mesh clipboard tools already present")
		return
	}

	pkgs := make([]string, 0, 2)
	if needWL {
		pkgs = append(pkgs, "wl-clipboard")
	}
	if needXclip {
		pkgs = append(pkgs, "xclip")
	}

	cmd, env := meshClipboardInstallCommand(pkgs)
	if cmd == "" {
		a.Logger.Warnln("Mesh clipboard: cannot install", strings.Join(pkgs, ", "), "(no supported package manager)")
		return
	}

	a.Logger.Infoln("Mesh clipboard: installing", strings.Join(pkgs, ", "))
	opts := a.NewCMDOpts()
	opts.Command = cmd
	opts.Timeout = 180
	if len(env) > 0 {
		opts.EnvVars = env
	}
	out := a.CmdV2(opts)
	if out.Status.Exit != 0 {
		a.Logger.Errorln("Mesh clipboard install failed:", strings.TrimSpace(out.Stderr+out.Stdout))
		return
	}

	if needWL && (!commandExists("wl-copy") || !commandExists("wl-paste")) {
		a.Logger.Warnln("Mesh clipboard: wl-clipboard still missing after install")
	}
	if needXclip && !commandExists("xclip") {
		a.Logger.Warnln("Mesh clipboard: xclip still missing after install")
	}
}

func meshClipboardInstallCommand(pkgs []string) (cmd string, env []string) {
	joined := strings.Join(pkgs, " ")
	switch detectUnixPatchManager() {
	case "apt":
		bin := "apt-get"
		if path, err := exec.LookPath("apt-get"); err == nil {
			bin = path
		} else if path, err := exec.LookPath("apt"); err == nil {
			bin = path
		}
		return fmt.Sprintf("%s install -y %s", bin, joined), []string{"DEBIAN_FRONTEND=noninteractive"}
	case "dnf":
		return "dnf install -y " + joined, nil
	case "yum":
		return "yum install -y " + joined, nil
	case "zypper":
		return "zypper --non-interactive install -y " + joined, nil
	case "pacman":
		return "pacman -Sy --noconfirm --needed " + joined, nil
	case "apk":
		return "apk add --no-cache " + joined, nil
	default:
		return "", nil
	}
}
