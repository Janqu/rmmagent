//go:build windows

package agent

import "testing"

func TestValidateServiceName(t *testing.T) {
	got, err := validateServiceName("  Spooler  ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "Spooler" {
		t.Fatalf("got %q", got)
	}
	for _, name := range []string{"", "bad/name", "bad\\name", "bad\x00name"} {
		if _, err := validateServiceName(name); err == nil {
			t.Fatalf("invalid service name accepted: %q", name)
		}
	}
}
