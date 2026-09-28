package agent

import "testing"

func TestParseMilliCelsius(t *testing.T) {
	got, ok := parseMilliCelsius("42000")
	if !ok || got != 42 {
		t.Fatalf("got %v %v", got, ok)
	}
	got, ok = parseMilliCelsius("41.5")
	if !ok || got != 41.5 {
		t.Fatalf("got %v %v", got, ok)
	}
	if _, ok := parseMilliCelsius("999999"); ok {
		t.Fatal("unreasonable value should be rejected")
	}
}

func TestParseFreeBSDTemperatures(t *testing.T) {
	got := parseFreeBSDTemperatures("dev.cpu.0.temperature: 48.0C\nhw.acpi.thermal.tz0.temperature: 42.1C\n")
	if len(got) != 2 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Celsius != 48 || got[1].Celsius != 42.1 {
		t.Fatalf("unexpected temps: %+v", got)
	}
}
