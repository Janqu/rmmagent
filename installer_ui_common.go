package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Janqu/qdt-rmm-agent/agent"
)

type installerTokenInfo struct {
	Site           int    `json:"site"`
	MonitoringType string `json:"monitoring_type"`
	Power          bool   `json:"power"`
	RDP            bool   `json:"rdp"`
	Ping           bool   `json:"ping"`
}

func installFromUI(a *agent.Agent, opts installerUIOptions) {
	if opts.API == "" || opts.Token == "" {
		log.Fatalln("RMM API URL and installer token are required")
	}
	a.Install(&agent.Installer{
		RMM:      opts.API,
		Token:    opts.Token,
		Timeout:  opts.Timeout,
		Silent:   opts.Silent,
		NoMesh:   true,
		Insecure: opts.Insecure,
	})
}

func runInstallerCommand(opts installerUIOptions) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	args := installerCommandArgs(opts)
	out, err := exec.Command(exe, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("installer failed: %w", err)
	}
	return string(out), nil
}

func installerCommandArgs(opts installerUIOptions) []string {
	args := []string{"-m", "install", "-nomesh", "-api", strings.TrimSpace(opts.API), "-auth", strings.TrimSpace(opts.Token)}
	if opts.Silent {
		args = append(args, "-silent")
	}
	if opts.Insecure {
		args = append(args, "-insecure")
	}
	return args
}

func fetchInstallerTokenInfo(api, token string, insecure bool) (installerTokenInfo, error) {
	var info installerTokenInfo
	base, err := installerAPIBase(api)
	if err != nil {
		return info, err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return info, fmt.Errorf("installer token is required")
	}
	req, err := http.NewRequest(http.MethodGet, base+"/api/v3/installer/", nil)
	if err != nil {
		return info, err
	}
	req.Header.Set("Authorization", "Token "+token)
	client := &http.Client{Timeout: 15 * time.Second}
	if insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	resp, err := client.Do(req)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return info, fmt.Errorf("installer token check failed: HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return info, err
	}
	if info.Site == 0 || (info.MonitoringType != "server" && info.MonitoringType != "workstation") {
		return info, fmt.Errorf("installer token response is missing site or agent type")
	}
	return info, nil
}

func installerAPIBase(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("valid RMM API URL is required")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/"), nil
}
