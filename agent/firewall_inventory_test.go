//go:build !windows

package agent

import "testing"

func TestParseFirewallConfig(t *testing.T) {
	cfg := parseFirewallConfig([]byte(`
<opnsense>
  <interfaces>
    <lan><if>em1</if><descr>LAN</descr><enable>1</enable></lan>
    <wan><if>em0</if><descr>WAN</descr></wan>
  </interfaces>
  <filter><rule></rule><rule></rule></filter>
  <nat><rule></rule></nat>
  <aliases><alias></alias></aliases>
</opnsense>`))

	if len(cfg.Interfaces) != 2 {
		t.Fatalf("interfaces=%d", len(cfg.Interfaces))
	}
	if cfg.Interfaces[0].Key != "lan" || !cfg.Interfaces[0].Enabled {
		t.Fatalf("unexpected lan: %+v", cfg.Interfaces[0])
	}
	if cfg.Interfaces[1].Enabled {
		t.Fatalf("wan should be disabled by empty enable: %+v", cfg.Interfaces[1])
	}
	if cfg.RuleCount != 2 || cfg.NATRuleCount != 1 || cfg.AliasCount != 1 {
		t.Fatalf("unexpected counts: %+v", cfg)
	}
}
