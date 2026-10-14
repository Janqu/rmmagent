package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var nativeSNMPBusy = make(chan struct{}, 1)
var nativeSNMPHostname = regexp.MustCompile(`^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?(\.[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?)*\.?$`)

func (a *Agent) snmpProbePath() (string, error) {
	if !filepath.IsAbs(a.ProgramDir) {
		return "", errors.New("native SNMP unavailable")
	}
	name := "qdt-snmp-probe"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(a.ProgramDir, name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && (info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0)) {
		return "", errors.New("native SNMP unavailable")
	}
	return path, nil
}

func (a *Agent) snmpCapabilities() map[string]interface{} {
	out := map[string]interface{}{"snmp_scan": false, "snmp_dump": false}
	path, err := a.snmpProbePath()
	if err != nil {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	text, err := runNativeSNMP(ctx, path, []string{"--capabilities"}, "", 4096)
	if err != nil {
		return out
	}
	var caps struct {
		Protocol int  `json:"protocol"`
		Dump     bool `json:"snmp_dump"`
		Scan     bool `json:"snmp_scan"`
	}
	if json.Unmarshal([]byte(text), &caps) != nil || caps.Protocol != 1 {
		return out
	}
	out["snmp_scan"], out["snmp_dump"] = caps.Scan, caps.Dump
	return out
}

func runNativeSNMP(ctx context.Context, path string, args []string, community string, limit int) (string, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.WaitDelay = 100 * time.Millisecond
	cmd.Env = append(os.Environ(), "QDT_SNMP_COMMUNITY="+community)
	output := newCappedBuffer(limit)
	cmd.Stdout = output
	// Stderr can contain credentials from a faulty tool. Never forward/log it.
	if err := cmd.Run(); err != nil || output.truncated {
		return "", errors.New("native SNMP failed or exceeded its output limit")
	}
	return output.String(), nil
}

func (a *Agent) nativeSNMPDiagnostic(mode string, data map[string]string) map[string]interface{} {
	failure := func(message string) map[string]interface{} {
		if mode == "snmp_dump" {
			return map[string]interface{}{"retcode": 1, "stdout": "", "stderr": message}
		}
		return map[string]interface{}{"error": message}
	}
	select {
	case nativeSNMPBusy <- struct{}{}:
		defer func() { <-nativeSNMPBusy }()
	default:
		return failure("native SNMP busy")
	}
	port, err := strconv.Atoi(data["port"])
	community := data["community"]
	if err != nil || port < 1 || port > 65535 || community == "" || len(community) > 1024 || strings.ContainsAny(community, "\x00\r\n") || len(data) != 3 {
		return failure("invalid native SNMP options")
	}
	var args []string
	var timeout time.Duration
	switch mode {
	case "snmp_dump":
		host := data["host"]
		ip, ipErr := netip.ParseAddr(host)
		if host == "" || len(host) > 253 || (ipErr != nil && !nativeSNMPHostname.MatchString(host)) || ip.IsUnspecified() || ip.IsMulticast() {
			return failure("invalid native SNMP host")
		}
		args = []string{"--dump", host, "--port", strconv.Itoa(port)}
		timeout = 120 * time.Second
	case "snmp_scan":
		prefix, err := netip.ParsePrefix(data["cidr"])
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 22 || prefix.Masked().Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return failure("invalid native SNMP range")
		}
		args = []string{"--scan", prefix.Masked().String(), "--port", strconv.Itoa(port), "--timeout", "1", "--retries", "0"}
		timeout = 25 * time.Second
	default:
		return failure("unsupported native SNMP operation")
	}
	path, err := a.snmpProbePath()
	if err != nil {
		return failure("native SNMP binary unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	text, err := runNativeSNMP(ctx, path, args, community, 768<<10)
	if err != nil {
		return failure("native SNMP failed, incomplete or timed out")
	}
	if mode == "snmp_dump" {
		var result map[string]interface{}
		if json.Unmarshal([]byte(text), &result) != nil || result["incomplete"] != false {
			return failure("invalid or incomplete native SNMP dump")
		}
		return map[string]interface{}{"retcode": 0, "stdout": text, "stderr": ""}
	}
	var rows []map[string]interface{}
	if json.Unmarshal([]byte(text), &rows) != nil || !strings.HasPrefix(strings.TrimSpace(text), "[") || len(rows) > 1024 {
		return failure("invalid native SNMP scan")
	}
	return map[string]interface{}{"devices": rows}
}
