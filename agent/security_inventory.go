package agent

import "strings"

type securityVendorRule struct {
	Vendor   string
	Category string
	Needles  []string
}

var securityVendorRules = []securityVendorRule{
	{Vendor: "Bitdefender", Category: "edr", Needles: []string{"bitdefender", "endpoint security tools", "epsecurityservice", "epupdateservice", "epprotectedservice", "bdservicehost"}},
	{Vendor: "ESET", Category: "antivirus", Needles: []string{"eset", "ekrn", "era agent", "eraagentsvc"}},
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
