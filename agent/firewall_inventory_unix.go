//go:build !windows

package agent

import (
	"encoding/xml"
	"os"
	"strings"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

const firewallConfigPath = "/conf/config.xml"

type firewallConfig struct {
	Interfaces struct {
		Items []firewallInterfaceXML `xml:",any"`
	} `xml:"interfaces"`
	Filter struct {
		Rules []struct{} `xml:"rule"`
	} `xml:"filter"`
	NAT struct {
		Rules []struct{} `xml:"rule"`
	} `xml:"nat"`
	Aliases struct {
		Items []struct{} `xml:"alias"`
	} `xml:"aliases"`
}

type firewallInterfaceXML struct {
	XMLName xml.Name `xml:""`
	If      string   `xml:"if"`
	Descr   string   `xml:"descr"`
	Enable  string   `xml:"enable"`
}

func collectFirewallInventory(appliance string) *rmm.FirewallInventory {
	inv := &rmm.FirewallInventory{
		Detected:        appliance != "",
		Appliance:       appliance,
		Version:         firewallVersion(appliance),
		ConfigPath:      firewallConfigPath,
		PatchAllAllowed: false,
		FirmwareManaged: true,
		SafetyNote:      "firmware/base upgrades must stay manual or maintenance-window controlled",
	}

	data, err := os.ReadFile(firewallConfigPath)
	if err != nil {
		return inv
	}
	inv.ConfigReadable = true

	cfg := parseFirewallConfig(data)
	inv.Interfaces = cfg.Interfaces
	inv.RuleCount = cfg.RuleCount
	inv.NATRuleCount = cfg.NATRuleCount
	inv.AliasCount = cfg.AliasCount
	return inv
}

type parsedFirewallConfig struct {
	Interfaces   []rmm.FirewallInterface
	RuleCount    int
	NATRuleCount int
	AliasCount   int
}

func parseFirewallConfig(data []byte) parsedFirewallConfig {
	var cfg firewallConfig
	if err := xml.Unmarshal(data, &cfg); err != nil {
		return parsedFirewallConfig{}
	}

	interfaces := make([]rmm.FirewallInterface, 0, len(cfg.Interfaces.Items))
	for _, iface := range cfg.Interfaces.Items {
		key := strings.TrimSpace(iface.XMLName.Local)
		if key == "" {
			continue
		}
		interfaces = append(interfaces, rmm.FirewallInterface{
			Key:         key,
			Name:        strings.TrimSpace(iface.If),
			Description: strings.TrimSpace(iface.Descr),
			Enabled:     strings.TrimSpace(iface.Enable) != "",
		})
	}

	return parsedFirewallConfig{
		Interfaces:   interfaces,
		RuleCount:    len(cfg.Filter.Rules),
		NATRuleCount: len(cfg.NAT.Rules),
		AliasCount:   len(cfg.Aliases.Items),
	}
}

func firewallVersion(appliance string) string {
	var paths []string
	switch appliance {
	case "opnsense":
		paths = []string{"/usr/local/opnsense/version/core", "/usr/local/opnsense/version/opnsense"}
	case "pfsense":
		paths = []string{"/etc/version"}
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil {
			if version := strings.TrimSpace(string(data)); version != "" {
				return version
			}
		}
	}
	return ""
}

func (a *Agent) FirewallInventory() *rmm.FirewallInventory {
	appliance := detectFirewallAppliance()
	if appliance == "" {
		return &rmm.FirewallInventory{}
	}
	return collectFirewallInventory(appliance)
}
