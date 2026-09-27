package agent

import (
	"bufio"
	"strings"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

func parsePkgQuery(output string) []rmm.PatchPackage {
	var packages []rmm.PatchPackage
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 2 || strings.TrimSpace(fields[0]) == "" {
			continue
		}
		pkg := rmm.PatchPackage{
			Name:           strings.TrimSpace(fields[0]),
			CurrentVersion: strings.TrimSpace(fields[1]),
		}
		if len(fields) > 2 {
			pkg.SourceRepository = strings.TrimSpace(fields[2])
		}
		packages = append(packages, pkg)
	}
	return packages
}

func parseDpkgQuery(output string) []rmm.PatchPackage {
	var packages []rmm.PatchPackage
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 2 || strings.TrimSpace(fields[0]) == "" {
			continue
		}
		packages = append(packages, rmm.PatchPackage{
			Name:           strings.TrimSpace(fields[0]),
			CurrentVersion: strings.TrimSpace(fields[1]),
		})
	}
	return packages
}

func markAptUpdates(packages []rmm.PatchPackage, output string) []rmm.PatchPackage {
	byName := make(map[string]int, len(packages))
	for i := range packages {
		byName[packages[i].Name] = i
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Listing...") || strings.HasPrefix(line, "WARNING:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		nameRepo := strings.SplitN(fields[0], "/", 2)
		name := strings.TrimSpace(nameRepo[0])
		idx, ok := byName[name]
		if !ok {
			continue
		}
		packages[idx].NeedsUpdate = true
		packages[idx].AvailableVersion = fields[1]
		if len(nameRepo) == 2 {
			packages[idx].SourceRepository = nameRepo[1]
		}
	}
	return packages
}

func parsePkgRepos(output string) []rmm.PatchRepository {
	var repos []rmm.PatchRepository
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		repo := rmm.PatchRepository{Name: strings.TrimSpace(parts[0]), Enabled: true}
		if len(parts) == 2 {
			repo.URL = strings.TrimSpace(parts[1])
			repo.Secure = strings.HasPrefix(repo.URL, "https://")
		}
		repos = append(repos, repo)
	}
	return repos
}

func parseAptSourceRepos(output string) []rmm.PatchRepository {
	var repos []rmm.PatchRepository
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "deb" {
			continue
		}
		repos = append(repos, rmm.PatchRepository{
			Name:    fields[1],
			URL:     fields[1],
			Enabled: true,
			Secure:  strings.HasPrefix(fields[1], "https://"),
		})
	}
	return repos
}

func markPkgUpdates(packages []rmm.PatchPackage, output string) []rmm.PatchPackage {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.Contains(line, "<") {
			continue
		}
		if idx := pkgUpdateIndex(packages, strings.Fields(line)[0]); idx >= 0 {
			packages[idx].NeedsUpdate = true
			packages[idx].AvailableVersion = pkgAvailableVersion(line)
		}
	}
	return packages
}

func pkgUpdateIndex(packages []rmm.PatchPackage, field string) int {
	match := -1
	matchLen := 0
	for i, pkg := range packages {
		if field == pkg.Name || strings.HasPrefix(field, pkg.Name+"-") {
			if len(pkg.Name) > matchLen {
				match = i
				matchLen = len(pkg.Name)
			}
		}
	}
	return match
}

func pkgAvailableVersion(line string) string {
	const marker = "index has "
	start := strings.Index(line, marker)
	if start < 0 {
		return ""
	}
	version := line[start+len(marker):]
	if end := strings.Index(version, ")"); end >= 0 {
		version = version[:end]
	}
	return strings.TrimSpace(version)
}
