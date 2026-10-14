package agent

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func nativeSNMPFixture(t *testing.T) *Agent {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX executable fixture")
	}
	dir := t.TempDir()
	t.Setenv("QDT_TEST_SNMP_DIR", dir)
	t.Setenv("QDT_TEST_SNMP_EXIT", "0")
	script := `#!/bin/sh
if [ "$1" = --capabilities ]; then
  printf '%s' "${QDT_TEST_SNMP_CAPS}"
  exit 0
fi
printf '%s\n' "$@" > "$QDT_TEST_SNMP_DIR/args"
printf '%s' "$QDT_SNMP_COMMUNITY" > "$QDT_TEST_SNMP_DIR/community"
printf '%s' "$QDT_TEST_SNMP_REPLY"
printf 'private failure %s' "$QDT_SNMP_COMMUNITY" >&2
exit "$QDT_TEST_SNMP_EXIT"
`
	if err := os.WriteFile(filepath.Join(dir, "qdt-snmp-probe"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QDT_TEST_SNMP_CAPS", `{"protocol":1,"snmp_dump":true,"snmp_scan":true}`)
	t.Setenv("QDT_TEST_SNMP_REPLY", `{"incomplete":false,"suggested_metric_map":{}}`)
	return &Agent{ProgramDir: dir}
}

func TestNativeSNMPCapabilities(t *testing.T) {
	a := nativeSNMPFixture(t)
	if caps := a.snmpCapabilities(); caps["snmp_dump"] != true || caps["snmp_scan"] != true {
		t.Fatalf("valid helper unavailable: %v", caps)
	}
	for _, invalid := range []string{`{"protocol":2,"snmp_dump":true}`, `not-json`, `{}`} {
		t.Setenv("QDT_TEST_SNMP_CAPS", invalid)
		if a.snmpCapabilities()["snmp_dump"] != false {
			t.Fatal("invalid helper advertised")
		}
	}
	if (&Agent{ProgramDir: t.TempDir()}).snmpCapabilities()["snmp_dump"] != false {
		t.Fatal("missing binary advertised")
	}
	if (&Agent{ProgramDir: "relative"}).snmpCapabilities()["snmp_dump"] != false {
		t.Fatal("relative helper path accepted")
	}
	path := filepath.Join(a.ProgramDir, "qdt-snmp-probe")
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := a.snmpProbePath(); err == nil {
		t.Fatal("writable helper accepted")
	}
	linkAgent := &Agent{ProgramDir: t.TempDir()}
	if err := os.Symlink(path, filepath.Join(linkAgent.ProgramDir, "qdt-snmp-probe")); err != nil {
		t.Fatal(err)
	}
	if _, err := linkAgent.snmpProbePath(); err == nil {
		t.Fatal("symlink helper accepted")
	}
}

func TestNativeSNMPDiagnostic(t *testing.T) {
	a := nativeSNMPFixture(t)
	data := map[string]string{"host": "192.0.2.1", "port": "161", "community": "private-$(never-execute)"}
	result := a.nativeSNMPDiagnostic("snmp_dump", data)
	if result["retcode"] != 0 || result["stderr"] != "" {
		t.Fatalf("dump failed: %v", result)
	}
	args, err := os.ReadFile(filepath.Join(a.ProgramDir, "args"))
	if err != nil {
		t.Fatal(err)
	}
	if string(args) != "--dump\n192.0.2.1\n--port\n161\n" {
		t.Fatalf("unexpected arguments: %q", args)
	}
	community, err := os.ReadFile(filepath.Join(a.ProgramDir, "community"))
	if err != nil || string(community) != data["community"] {
		t.Fatal("community was not passed through environment")
	}
	for _, bad := range []string{`{"incomplete":true}`, `[]`, `not-json`} {
		t.Setenv("QDT_TEST_SNMP_REPLY", bad)
		if a.nativeSNMPDiagnostic("snmp_dump", data)["retcode"] != 1 {
			t.Fatal("bad dump accepted")
		}
	}
	t.Setenv("QDT_TEST_SNMP_EXIT", "1")
	t.Setenv("QDT_TEST_SNMP_REPLY", data["community"])
	result = a.nativeSNMPDiagnostic("snmp_dump", data)
	if result["retcode"] != 1 || result["stdout"] != "" || strings.Contains(result["stderr"].(string), data["community"]) {
		t.Fatal("failed helper exposed credentials")
	}
	t.Setenv("QDT_TEST_SNMP_EXIT", "0")
	t.Setenv("QDT_TEST_SNMP_REPLY", `[{"ip":"192.0.2.1"}]`)
	result = a.nativeSNMPDiagnostic("snmp_scan", map[string]string{"cidr": "192.0.2.5/29", "port": "161", "community": "private"})
	if _, ok := result["devices"]; !ok {
		t.Fatalf("scan failed: %v", result)
	}
	args, _ = os.ReadFile(filepath.Join(a.ProgramDir, "args"))
	if !strings.Contains(string(args), "192.0.2.0/29\n") || !strings.Contains(string(args), "--timeout\n1\n--retries\n0\n") {
		t.Fatal("scan bounds missing")
	}
}

func TestNativeSNMPGuards(t *testing.T) {
	a := nativeSNMPFixture(t)
	for _, data := range []map[string]string{{"host": "--scan", "port": "161", "community": "x"}, {"host": "192.0.2.1", "port": "0", "community": "x"}, {"host": "192.0.2.1", "port": "161", "community": "x\n"}, {"host": "192.0.2.1", "port": "161", "community": "x", "code": "ignored?"}} {
		if a.nativeSNMPDiagnostic("snmp_dump", data)["retcode"] != 1 {
			t.Fatal("invalid input executed")
		}
	}
	if _, err := os.Stat(filepath.Join(a.ProgramDir, "args")); !os.IsNotExist(err) {
		t.Fatal("helper started for invalid input")
	}
	nativeSNMPBusy <- struct{}{}
	result := a.nativeSNMPDiagnostic("snmp_scan", nil)
	<-nativeSNMPBusy
	if result["error"] != "native SNMP busy" {
		t.Fatal("overlapping diagnostic accepted")
	}
	t.Setenv("QDT_TEST_SNMP_REPLY", strings.Repeat("x", 100))
	path, _ := a.snmpProbePath()
	if _, err := runNativeSNMP(context.Background(), path, []string{"--dump"}, "secret", 10); err == nil {
		t.Fatal("truncated output accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	if _, err := runNativeSNMP(ctx, path, []string{"--dump"}, "secret", 1000); err == nil {
		t.Fatal("expired request executed")
	}
}
