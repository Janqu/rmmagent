//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"strings"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

func (a *Agent) SecurityInventory() []rmm.SecurityProductInventory {
	candidates := collectSecurityServiceCandidates()
	if len(candidates) == 0 {
		return []rmm.SecurityProductInventory{}
	}

	products := make([]rmm.SecurityProductInventory, 0)
	seen := map[string]int{}
	for _, candidate := range candidates {
		vendor, category := classifySecurityProduct(candidate)
		if vendor == "Unknown" {
			continue
		}
		key := strings.ToLower(vendor)
		idx, ok := seen[key]
		if !ok {
			products = append(products, rmm.SecurityProductInventory{
				Name:     vendor,
				Vendor:   vendor,
				Category: category,
				Healthy:  true,
				Running:  true,
				Services: []string{candidate},
			})
			seen[key] = len(products) - 1
			continue
		}
		products[idx].Services = append(products[idx].Services, candidate)
	}
	return products
}

func collectSecurityServiceCandidates() []string {
	var candidates []string
	candidates = append(candidates, basenameMatches("/etc/init.d")...)
	candidates = append(candidates, basenameMatches("/usr/local/etc/rc.d")...)
	candidates = append(candidates, basenameMatches("/etc/rc.d")...)
	candidates = append(candidates, systemdUnitMatches("/etc/systemd/system")...)
	candidates = append(candidates, systemdUnitMatches("/usr/lib/systemd/system")...)
	candidates = append(candidates, procCommandMatches("/proc")...)
	return dedupeStrings(candidates)
}

func basenameMatches(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var matches []string
	for _, entry := range entries {
		name := entry.Name()
		if securityCandidateName(name) {
			matches = append(matches, name)
		}
	}
	return matches
}

func systemdUnitMatches(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var matches []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".service") && securityCandidateName(name) {
			matches = append(matches, strings.TrimSuffix(name, ".service"))
		}
	}
	return matches
}

func procCommandMatches(procDir string) []string {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil
	}
	var matches []string
	for _, entry := range entries {
		if !entry.IsDir() || !allDigits(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(procDir, entry.Name(), "comm"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(data))
		if securityCandidateName(name) {
			matches = append(matches, name)
		}
	}
	return matches
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
