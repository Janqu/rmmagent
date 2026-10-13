/*
Copyright 2023 AmidaWare Inc.

Licensed under the Tactical RMM License Version 1.0 (the “License”).
You may only use the Licensed Software in accordance with the License.
A copy of the License is available at:

https://license.tacticalrmm.com

*/

package agent

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	trmm "github.com/wh1te909/trmm-shared"
)

type Installer struct {
	Headers          map[string]string
	RMM              string
	ClientID         int
	SiteID           int
	Description      string
	AgentType        string
	Power            bool
	RDP              bool
	Ping             bool
	Token            string
	LocalMesh        string
	Cert             string
	Proxy            string
	Timeout          time.Duration
	SaltMaster       string
	Silent           bool
	NoMesh           bool
	MeshDir          string
	MeshNodeID       string
	Insecure         bool
	NatsStandardPort string
	TmpDir           string
}

type installerBootstrap struct {
	Site           int    `json:"site"`
	MonitoringType string `json:"monitoring_type"`
	Power          bool   `json:"power"`
	RDP            bool   `json:"rdp"`
	Ping           bool   `json:"ping"`
}

func (a *Agent) Install(i *Installer) {
	if runtime.GOOS == "linux" {
		if _, err := os.Stat(etcConfig); err == nil {
			a.installerMsg("Existing agent configuration found; remove the existing installation before reinstalling.", "error", i.Silent)
		}
		if _, err := exec.LookPath("systemctl"); err != nil {
			a.installerMsg("Linux installation requires systemd.", "error", i.Silent)
		}
		if _, err := os.Stat("/run/systemd/system"); err != nil {
			a.installerMsg("Linux installation requires a running systemd instance.", "error", i.Silent)
		}
	}
	a.checkExistingAndRemove(i.Silent)

	i.Headers = map[string]string{
		"content-type":  "application/json",
		"Authorization": fmt.Sprintf("Token %s", i.Token),
	}
	a.AgentID = GenerateAgentID()
	a.Logger.Debugln("Agent ID:", a.AgentID)

	u, err := url.Parse(i.RMM)
	if err != nil {
		a.installerMsg(err.Error(), "error", i.Silent)
	}

	if u.Scheme != "https" && u.Scheme != "http" {
		a.installerMsg("Invalid URL (must contain https or http)", "error", i.Silent)
	}

	// will match either ipv4 , or ipv4:port
	var ipPort = regexp.MustCompile(`[0-9]+(?:\.[0-9]+){3}(:[0-9]+)?`)

	// if ipv4:port, strip the port to get ip for salt master
	if ipPort.MatchString(u.Host) && strings.Contains(u.Host, ":") {
		i.SaltMaster = strings.Split(u.Host, ":")[0]
	} else if strings.Contains(u.Host, ":") {
		i.SaltMaster = strings.Split(u.Host, ":")[0]
	} else {
		i.SaltMaster = u.Host
	}

	a.Logger.Debugln("API:", i.SaltMaster)

	baseURL := u.Scheme + "://" + u.Host
	a.Logger.Debugln("Base URL:", baseURL)

	iClient := resty.New()
	iClient.SetCloseConnection(true)
	iClient.SetTimeout(15 * time.Second)
	iClient.SetDebug(false)
	iClient.SetHeaders(i.Headers)

	// set proxy if applicable
	if len(i.Proxy) > 0 {
		a.Logger.Infoln("Using proxy:", i.Proxy)
		iClient.SetProxy(i.Proxy)
	}

	insecureConf := &tls.Config{
		InsecureSkipVerify: true,
	}

	if i.Insecure {
		a.Logger.Warnln("TLS certificate verification disabled for installer API client")
		iClient.SetTLSClientConfig(insecureConf)
	}

	installerInfo := &installerBootstrap{}
	creds, cerr := iClient.R().SetResult(installerInfo).Get(fmt.Sprintf("%s/api/v3/installer/", baseURL))
	if cerr != nil {
		a.installerMsg(cerr.Error(), "error", i.Silent)
	}
	if creds.StatusCode() == 401 {
		a.installerMsg("Installer token has expired. Please generate a new one.", "error", i.Silent)
	}
	if creds.StatusCode() != 200 {
		a.installerMsg(DjangoStringResp(creds.String()), "error", i.Silent)
	}
	if i.SiteID == 0 {
		i.SiteID = installerInfo.Site
	}
	if i.AgentType == "" {
		i.AgentType = installerInfo.MonitoringType
	}
	i.Power = i.Power || installerInfo.Power
	i.RDP = i.RDP || installerInfo.RDP
	i.Ping = i.Ping || installerInfo.Ping
	if i.SiteID == 0 || (i.AgentType != "server" && i.AgentType != "workstation") {
		a.installerMsg("Installer token does not include a valid site and agent type.", "error", i.Silent)
	}

	verPayload := map[string]string{"version": a.Version}
	iVersion, ierr := iClient.R().SetBody(verPayload).Post(fmt.Sprintf("%s/api/v3/installer/", baseURL))
	if ierr != nil {
		a.installerMsg(ierr.Error(), "error", i.Silent)
	}
	if iVersion.StatusCode() != 200 {
		a.installerMsg(DjangoStringResp(iVersion.String()), "error", i.Silent)
	}

	destination := nixAgentBin
	if runtime.GOOS == "windows" {
		destination = filepath.Join(a.ProgramDir, winExeName)
	}
	self, err := os.Executable()
	if err != nil {
		a.installerMsg(err.Error(), "error", i.Silent)
	}
	if err := installExecutable(self, destination); err != nil {
		a.installerMsg(err.Error(), "error", i.Silent)
	}

	rClient := resty.New()
	rClient.SetCloseConnection(true)
	rClient.SetTimeout(i.Timeout * time.Second)
	rClient.SetDebug(false)
	// set rest knox headers
	rClient.SetHeaders(i.Headers)

	// set local cert if applicable
	if len(i.Cert) > 0 {
		if !trmm.FileExists(i.Cert) {
			a.installerMsg(fmt.Sprintf("%s does not exist", i.Cert), "error", i.Silent)
		}
		rClient.SetRootCertificate(i.Cert)
	}

	if len(i.Proxy) > 0 {
		rClient.SetProxy(i.Proxy)
	}

	if i.Insecure {
		a.Logger.Warnln("TLS certificate verification disabled for installer runtime API client")
		rClient.SetTLSClientConfig(insecureConf)
	}

	var installerMeshSystemEXE string
	if len(i.MeshDir) > 0 {
		installerMeshSystemEXE = filepath.Join(i.MeshDir, "MeshAgent.exe")
	} else {
		installerMeshSystemEXE = a.MeshSystemEXE
	}

	var meshNodeID, meshOutput string

	if !i.NoMesh {
		switch runtime.GOOS {
		case "windows":
			meshOutput = filepath.Join(a.ProgramDir, a.MeshInstaller)
		case "darwin", "linux":
			tmp, err := createNixTmpFile(a.UnixTmpDir)
			if err != nil {
				a.Logger.Fatalln("Failed to create mesh temp file", err)
			}
			meshOutput = tmp.Name()
			os.Chmod(meshOutput, 0755)
			defer os.Remove(meshOutput)
			defer os.Remove(meshOutput + ".msh")
		}

		if meshOutput != "" {
			if runtime.GOOS == "windows" && i.LocalMesh != "" {
				err := copyFile(i.LocalMesh, meshOutput)
				if err != nil {
					a.installerMsg(err.Error(), "error", i.Silent)
				}
			} else {
				a.Logger.Infoln("Downloading mesh agent...")
				payload := map[string]string{"goarch": a.GoArch, "plat": a.Platform}
				r, err := rClient.R().SetBody(payload).SetOutput(meshOutput).Post(fmt.Sprintf("%s/api/v3/meshexe/", baseURL))
				if err != nil {
					a.installerMsg(fmt.Sprintf("Failed to download mesh agent: %s", err.Error()), "error", i.Silent)
				}
				if r.StatusCode() != 200 {
					a.installerMsg(fmt.Sprintf("Unable to download the mesh agent from the RMM. %s", r.String()), "error", i.Silent)
				}
				meshSHA := r.Header().Get("X-Mesh-Agent-SHA256")
				if err := verifySHA256(meshOutput, meshSHA); err != nil {
					a.installerMsg(fmt.Sprintf("Mesh agent integrity check failed: %s", err.Error()), "error", i.Silent)
				}
				a.rememberMeshInstallerSHA(meshSHA)
			}

			a.Logger.Infoln("Installing mesh agent...")
			a.Logger.Debugln("Mesh agent:", meshOutput)
			time.Sleep(1 * time.Second)

			if runtime.GOOS == "windows" {
				meshNodeID, err = a.installMesh(meshOutput, installerMeshSystemEXE, i.Proxy)
				if err != nil {
					a.installerMsg(fmt.Sprintf("Failed to install mesh agent: %s", err.Error()), "error", i.Silent)
				}
			} else {
				if runtime.GOOS == "linux" {
					a.ensureMeshClipboardTools()
				}
				fakeDisplay := []string{"XAUTHORITY=foo", "DISPLAY=bar", "LC_ALL=en_US.UTF-8", "LANGUAGE=en_US"}
				if trmm.FileExists(installerMeshSystemEXE) {
					uopts := a.NewCMDOpts()
					uopts.Command = fmt.Sprintf("%s -uninstall", installerMeshSystemEXE)
					uopts.Timeout = i.Timeout
					uopts.EnvVars = fakeDisplay
					a.CmdV2(uopts)
					time.Sleep(1 * time.Second)
				}
				opts := a.NewCMDOpts()
				opts.Command = fmt.Sprintf("%s -install --installPath=%s", meshOutput, nixMeshDir)
				opts.Timeout = i.Timeout
				opts.EnvVars = fakeDisplay
				out := a.CmdV2(opts)
				if out.Status.Exit != 0 {
					a.Logger.Fatalln("Error installing mesh agent:", out.Stderr)
				}
				fmt.Println(out.Stdout)
				meshNodeID = StripAll(a.NixMeshNodeID())
			}
		}
	}

	if len(i.MeshNodeID) > 0 {
		meshNodeID = i.MeshNodeID
	}

	a.Logger.Infoln("Adding agent to dashboard")
	// add agent
	type NewAgentResp struct {
		AgentPK int    `json:"pk"`
		Token   string `json:"token"`
	}
	agentPayload := map[string]interface{}{
		"agent_id":        a.AgentID,
		"hostname":        a.Hostname,
		"site":            i.SiteID,
		"monitoring_type": i.AgentType,
		"mesh_node_id":    meshNodeID,
		"description":     i.Description,
		"goarch":          a.GoArch,
		"plat":            a.Platform,
	}

	r, err := rClient.R().SetBody(agentPayload).SetResult(&NewAgentResp{}).Post(fmt.Sprintf("%s/api/v3/newagent/", baseURL))
	if err != nil {
		a.installerMsg(err.Error(), "error", i.Silent)
	}
	if r.StatusCode() != 200 {
		a.installerMsg(r.String(), "error", i.Silent)
	}

	agentPK := r.Result().(*NewAgentResp).AgentPK
	agentToken := r.Result().(*NewAgentResp).Token

	a.Logger.Debugln("Agent PK:", agentPK)

	createAgentConfig(baseURL, a.AgentID, i.SaltMaster, agentToken, strconv.Itoa(agentPK), i.Cert, i.Proxy, i.MeshDir, i.NatsStandardPort, i.Insecure, i.TmpDir)
	time.Sleep(1 * time.Second)
	// refresh our agent with new values
	a = New(a.Logger, a.Version)

	// set new headers, no longer knox auth...use agent auth
	rClient.SetHeaders(a.Headers)

	time.Sleep(3 * time.Second)
	// check in once
	a.DoNatsCheckIn()

	if runtime.GOOS == "linux" {
		// Used for Nushell and Deno binaries
		if err := os.MkdirAll(nixAgentBinDir, 0755); err != nil {
			a.installerMsg(err.Error(), "error", i.Silent)
		}
		if err := os.WriteFile("/etc/systemd/system/tacticalagent.service", []byte(linuxAgentUnit), 0644); err != nil {
			a.installerMsg(err.Error(), "error", i.Silent)
		}
		for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "tacticalagent.service"}} {
			if output, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
				a.installerMsg(fmt.Sprintf("systemctl: %v: %s", err, output), "error", i.Silent)
			}
		}
	}

	if runtime.GOOS == "darwin" {
		os.MkdirAll(nixAgentBinDir, 0755)
		svc := fmt.Sprintf(`
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
		<key>Label</key>
		<string>%s</string>

		<key>ServiceDescription</key>
        <string>QDT RMM Agent Service</string>

		<key>ProgramArguments</key>
		<array>
			<string>%s</string>
			<string>-m</string>
			<string>svc</string>
		</array>

		<key>WorkingDirectory</key>
		<string>%s/</string>

		<key>RunAtLoad</key>
		<true/>

		<key>KeepAlive</key>
		<true/>
	</dict>
</plist>
`, macPlistName, nixAgentBin, nixAgentDir)

		os.WriteFile(macPlistPath, []byte(svc), 0644)
		opts := a.NewCMDOpts()
		opts.Command = fmt.Sprintf("launchctl bootstrap system %s", macPlistPath)
		a.CmdV2(opts)
	}

	if runtime.GOOS == "freebsd" {
		os.MkdirAll(nixAgentBinDir, 0755)

		// uses the base-system daemon(8) tool to background the agent,
		// track its pid, and restart it if it exits (-r)
		rc := fmt.Sprintf(`#!/bin/sh
#
# PROVIDE: %s
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="%s"
rcvar="${name}_enable"
pidfile="/var/run/${name}.pid"
command="/usr/sbin/daemon"
command_args="-f -P ${pidfile} -r %s -m svc"

load_rc_config $name
run_rc_command "$1"
`, freebsdSvcName, freebsdSvcName, nixAgentBin)

		os.WriteFile(freebsdRcPath, []byte(rc), 0755)

		enableOpts := a.NewCMDOpts()
		enableOpts.Command = fmt.Sprintf("sysrc %s_enable=YES", freebsdSvcName)
		a.CmdV2(enableOpts)

		startOpts := a.NewCMDOpts()
		startOpts.Command = fmt.Sprintf("service %s start", freebsdSvcName)
		a.CmdV2(startOpts)
	}

	if runtime.GOOS == "windows" {
		os.MkdirAll(filepath.Join(a.ProgramDir, "bin"), 0755)

		// send software api
		a.SendSoftware()

		a.Logger.Debugln("Creating temp dir")
		err := createWinTempDir()
		if err != nil {
			a.Logger.Errorln("Install() createWinTempDir():", err)
		}

		a.Logger.Debugln("Disabling automatic windows updates")
		a.PatchMgmnt(true)

		a.Logger.Infoln("Installing service...")
		a.ServiceConfig.Executable = filepath.Join(a.ProgramDir, winExeName)
		err = a.InstallService()
		if err != nil {
			a.installerMsg(err.Error(), "error", i.Silent)
		}

		time.Sleep(1 * time.Second)
		a.Logger.Infoln("Starting service...")
		out := a.ControlService(winSvcName, "start")
		if !out.Success {
			a.installerMsg(out.ErrorMsg, "error", i.Silent)
		}

		if i.Power {
			a.Logger.Infoln("Disabling sleep/hibernate...")
			DisableSleepHibernate()
		}

		if i.Ping {
			a.Logger.Infoln("Enabling ping...")
			EnablePing()
		}

		if i.RDP {
			a.Logger.Infoln("Enabling RDP...")
			EnableRDP()
		}
	}

	a.installerMsg("Installation was successful!\nAllow a few minutes for the agent to properly display in the RMM", "info", i.Silent)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return nil
}

const linuxAgentUnit = `[Unit]
Description=QDT RMM Agent
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/opt/tacticalagent/tacticalagent -m svc
WorkingDirectory=/opt/tacticalagent
User=root
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`

// Downloaded executables must survive removal of the temporary installer directory.
func installExecutable(source, destination string) error {
	src, err := os.Stat(source)
	if err != nil {
		return err
	}
	if dst, err := os.Stat(destination); err == nil && os.SameFile(src, dst) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.CreateTemp(filepath.Dir(destination), ".qdt-agent-*")
	if err != nil {
		return err
	}
	defer os.Remove(out.Name())
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Chmod(0755); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(out.Name(), destination)
}

func downloadFileAtomic(client *resty.Client, url, destination string) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return fmt.Errorf("create download dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".download-*")
	if err != nil {
		return fmt.Errorf("create temp download: %w", err)
	}
	tmpName := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp download: %w", err)
	}
	defer os.Remove(tmpName)

	resp, err := client.R().SetOutput(tmpName).Get(url)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	if resp.IsError() {
		return fmt.Errorf("download %s: status %d", url, resp.StatusCode())
	}
	if err := os.Rename(tmpName, destination); err != nil {
		return fmt.Errorf("install downloaded file: %w", err)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file for sha256: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func verifySHA256(path, expected string) error {
	expected = strings.TrimSpace(strings.ToLower(expected))
	if expected == "" {
		return nil
	}
	got, err := fileSHA256(path)
	if err != nil {
		return err
	}
	if got != expected {
		return fmt.Errorf("sha256 mismatch: got %s want %s", got, expected)
	}
	return nil
}

func replaceFileWithBackup(source, destination string) error {
	backup := destination + ".bak"
	_ = os.Remove(backup)
	if err := os.Rename(destination, backup); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("backup existing file: %w", err)
	}
	if err := os.Rename(source, destination); err != nil {
		if _, statErr := os.Stat(backup); statErr == nil {
			_ = os.Rename(backup, destination)
		}
		return fmt.Errorf("replace file: %w", err)
	}
	return nil
}
