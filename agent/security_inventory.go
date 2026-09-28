package agent

import "strings"

type securityVendorRule struct {
	Vendor   string
	Category string
	Needles  []string
}

var securityVendorRules = []securityVendorRule{
	{Vendor: "Bitdefender", Category: "edr", Needles: []string{"bitdefender", "endpoint security tools", "epsecurityservice", "epupdateservice", "epprotectedservice", "bdservicehost"}},
	{Vendor: "ESET", Category: "antivirus", Needles: []string{"eset", "ekrn", "era agent", "eraagentsvc", "eraagent", "eea", "efs"}},
	{Vendor: "Acronis", Category: "backup_security", Needles: []string{"acronis", "cyber protect", "active protection", "acrsch", "aakore"}},
	{Vendor: "Microsoft Defender", Category: "antivirus", Needles: []string{"windows defender", "microsoft defender", "windefend", "msmpeng"}},
	{Vendor: "Sophos", Category: "edr", Needles: []string{"sophos"}},
	{Vendor: "Kaspersky", Category: "antivirus", Needles: []string{"kaspersky", "kav"}},
	{Vendor: "CrowdStrike", Category: "edr", Needles: []string{"crowdstrike", "falcon"}},
	{Vendor: "SentinelOne", Category: "edr", Needles: []string{"sentinelone", "sentinel agent"}},
	{Vendor: "Trend Micro", Category: "antivirus", Needles: []string{"trend micro", "officescan"}},
	{Vendor: "Malwarebytes", Category: "antivirus", Needles: []string{"malwarebytes"}},
	{Vendor: "Atera", Category: "rmm_security", Needles: []string{"atera"}},
}

func classifySecurityProduct(text string) (string, string) {
	lower := strings.ToLower(text)
	for _, rule := range securityVendorRules {
		for _, needle := range rule.Needles {
			if strings.Contains(lower, needle) {
				return rule.Vendor, rule.Category
			}
		}
	}
	return "Unknown", "security"
}

func securityCandidateName(name string) bool {
	vendor, _ := classifySecurityProduct(name)
	return vendor != "Unknown"
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		key := strings.ToLower(strings.TrimSpace(s))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}
