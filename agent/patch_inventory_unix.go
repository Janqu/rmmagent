//go:build !windows

package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

func (a *Agent) PatchInventory() rmm.PatchInventory {
	manager := detectUnixPatchManager()
	inv := rmm.PatchInventory{
		AgentID:         a.AgentID,
		Platform:        a.Platform,
		Supported:       manager != "unknown",
		CheckedAt:       time.Now().UTC(),
		PackageManager:  manager,
		PatchAllAllowed: manager != "unknown",
	}
	if inv.Appliance = detectFirewallAppliance(); inv.Appliance != "" {
		inv.PatchAllAllowed = false
		inv.Firewall = collectFirewallInventory(inv.Appliance)
	}

	switch manager {
	case "pkg":
		packages, repos, err := collectPkgInventory()
		inv.Packages = packages
		inv.Repositories = repos
		if err != nil {
			inv.Error = err.Error()
		}
	case "apt":
		packages, repos, err := collectAptInventory()
		inv.Packages = packages
		inv.Repositories = repos
		if err != nil {
			inv.Error = err.Error()
		}
	case "dnf", "yum", "zypper", "apk", "pacman":
		inv.Error = "package inventory parser not implemented yet for " + manager
	default:
		inv.Error = "unsupported package manager"
	}

	return inv
}

func detectUnixPatchManager() string {
	if runtime.GOOS == "freebsd" {
		if commandExists("/usr/sbin/pkg") || commandExists("/usr/local/sbin/pkg") || commandExists("pkg") {
			return "pkg"
		}
	}
	for _, name := range []string{"apt", "apt-get", "zypper", "dnf", "yum", "apk", "pacman", "pkg"} {
		if commandExists(name) {
			if name == "apt-get" {
				return "apt"
			}
			return name
		}
	}
	return "unknown"
}

func detectFirewallAppliance() string {
	switch {
	case commandExists("/usr/local/sbin/opnsense-update") || fileExists("/usr/local/opnsense/version/core"):
		return "opnsense"
	case commandExists("/usr/local/sbin/pfSense-upgrade") || fileExists("/etc/version") && fileContains("/etc/platform", "pfSense"):
		return "pfsense"
	default:
		return ""
	}
}

func collectPkgInventory() ([]rmm.PatchPackage, []rmm.PatchRepository, error) {
	pkg := pkgBinary()
	installed, err := runPatchInventoryCommand(pkg, "query", "-a", "%n\t%v\t%R")
	if err != nil {
		return nil, nil, err
	}
	packages := parsePkgQuery(installed)

	if updates, err := runPatchInventoryCommand(pkg, "version", "-vL="); err == nil {
		packages = markPkgUpdates(packages, updates)
	}

	repoOut, _ := runPatchInventoryCommand(pkg, "repo", "-l", "-q")
	return packages, parsePkgRepos(repoOut), nil
}

func collectAptInventory() ([]rmm.PatchPackage, []rmm.PatchRepository, error) {
	installed, err := runPatchInventoryCommand("dpkg-query", "-W", "-f", "${Package}\t${Version}\n")
	if err != nil {
		return nil, nil, err
	}
	packages := parseDpkgQuery(installed)

	if updates, err := runPatchInventoryCommand(aptBinary(), "list", "--upgradable"); err == nil {
		packages = markAptUpdates(packages, updates)
	}

	return packages, readAptRepos(), nil
}

func aptBinary() string {
	if commandExists("apt") {
		return "apt"
	}
	return "apt-get"
}

func readAptRepos() []rmm.PatchRepository {
	var repos []rmm.PatchRepository
	for _, path := range aptSourceFiles() {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		repos = append(repos, parseAptSourceRepos(string(data))...)
	}
	return repos
}

func aptSourceFiles() []string {
	files := []string{"/etc/apt/sources.list"}
	entries, err := os.ReadDir("/etc/apt/sources.list.d")
	if err != nil {
		return files
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".list") {
			files = append(files, filepath.Join("/etc/apt/sources.list.d", entry.Name()))
		}
	}
	return files
}

func pkgBinary() string {
	for _, path := range []string{"/usr/sbin/pkg", "/usr/local/sbin/pkg", "pkg"} {
		if commandExists(path) {
			return path
		}
	}
	return "pkg"
}

func runPatchInventoryCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LANG=C", "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin")
	cmd.WaitDelay = 10 * time.Second
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func commandExists(name string) bool {
	if strings.Contains(name, "/") {
		info, err := os.Stat(name)
		return err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0
	}
	_, err := exec.LookPath(name)
	return err == nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func fileContains(path, needle string) bool {
	data, err := os.ReadFile(path)
	return err == nil && strings.Contains(strings.ToLower(string(data)), strings.ToLower(needle))
}
