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
