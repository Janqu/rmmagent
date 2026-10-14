//go:build linux
// +build linux

package agent

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// linuxMeshDesktopHints reports Wayland/DRM readiness for Mesh remote desktop.
// Callers: Health() in health.go. User instruction: "weiter" (P3).
func linuxMeshDesktopHints() []string {
	var hints []string
	session := linuxDisplaySession()

	if session == "none" {
		hints = append(hints, "mesh: no Wayland/X11 session detected; desktop remoting needs a logged-in graphical session")
	}

	if _, err := os.Stat("/dev/dri"); err != nil {
		hints = append(hints, "mesh: /dev/dri missing; DRM desktop capture unavailable")
	}

	for _, group := range []string{"render", "video"} {
		if !linuxGroupExists(group) {
			hints = append(hints, "mesh: group "+group+" missing on this host")
			continue
		}
		if !linuxProcessInGroup(group) {
			hints = append(hints, "mesh: agent process not in group "+group+" (DRM/EGL may fail under snap Mesa)")
		}
	}

	if session == "wayland" {
		if _, err := exec.LookPath("wl-copy"); err != nil {
			hints = append(hints, "mesh: install wl-clipboard for Wayland clipboard support")
		}
	}

	return hints
}

// linuxDisplaySession detects a graphical session for Mesh desktop remoting.
// Returns wayland, x11, or none. Used by Health/MeshHealth and desktop hints.
func linuxDisplaySession() string {
	if os.Getenv("WAYLAND_DISPLAY") != "" || strings.EqualFold(os.Getenv("XDG_SESSION_TYPE"), "wayland") {
		return "wayland"
	}
	if os.Getenv("DISPLAY") != "" || strings.EqualFold(os.Getenv("XDG_SESSION_TYPE"), "x11") {
		return "x11"
	}
	if matches, _ := filepath.Glob("/run/user/*/wayland-*"); len(matches) > 0 {
		return "wayland"
	}
	if matches, _ := filepath.Glob("/tmp/.X11-unix/X*"); len(matches) > 0 {
		return "x11"
	}
	return "none"
}

func linuxGroupExists(name string) bool {
	_, err := user.LookupGroup(name)
	return err == nil
}

func linuxProcessInGroup(name string) bool {
	g, err := user.LookupGroup(name)
	if err != nil {
		return false
	}
	want, err := strconv.Atoi(g.Gid)
	if err != nil {
		return false
	}
	if os.Getgid() == want {
		return true
	}
	gids, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, gid := range gids {
		if gid == want {
			return true
		}
	}
	return false
}
