package agent

import "testing"

func TestClassifySecurityProduct(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		vendor   string
		category string
	}{
		{"bitdefender", "Bitdefender Endpoint Security Tools", "Bitdefender", "edr"},
		{"eset", "ESET Service ekrn", "ESET", "antivirus"},
		{"acronis", "Acronis Cyber Protect Service", "Acronis", "backup_security"},
		{"defender", "Microsoft Defender Antivirus Service", "Microsoft Defender", "antivirus"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vendor, category := classifySecurityProduct(tt.input)
			if vendor != tt.vendor || category != tt.category {
				t.Fatalf("got %s/%s want %s/%s", vendor, category, tt.vendor, tt.category)
			}
		})
	}
}

func TestSecurityCandidateName(t *testing.T) {
	if !securityCandidateName("acronis_mms") {
		t.Fatal("acronis_mms should be detected")
	}
	if !securityCandidateName("eea.service") {
		t.Fatal("eea.service should be detected as ESET")
	}
	if securityCandidateName("sshd") {
		t.Fatal("sshd should not be detected")
	}
}

func TestDedupeStrings(t *testing.T) {
	got := dedupeStrings([]string{"Acronis", "acronis", "", "ESET"})
	if len(got) != 2 {
		t.Fatalf("len=%d got=%v", len(got), got)
	}
}
