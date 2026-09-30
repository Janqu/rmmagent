package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

var agentURL string
var agentSHA256 string

func run(name string, args ...string) {
	_ = exec.Command(name, args...).Run()
}

func main() {
	if agentURL == "" || len(agentSHA256) != 64 {
		os.Exit(2)
	}
	target := filepath.Join(os.Getenv("ProgramFiles"), "TacticalAgent", "tacticalrmm.exe")
	if _, err := os.Stat(target); err != nil {
		target = filepath.Join(os.Getenv("ProgramFiles(x86)"), "TacticalAgent", "tacticalrmm.exe")
	}
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("qdt-rmm-agent-%d.exe", time.Now().UnixNano()))
	resp, err := (&http.Client{Timeout: 15 * time.Minute}).Get(agentURL)
	if err != nil {
		os.Exit(3)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		os.Exit(4)
	}
	f, err := os.Create(tmp)
	if err != nil {
		os.Exit(5)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		_ = f.Close()
		os.Exit(6)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Exit(6)
	}
	if err := f.Close(); err != nil {
		os.Exit(6)
	}
	defer os.Remove(tmp)
	if hex.EncodeToString(h.Sum(nil)) != agentSHA256 {
		os.Exit(8)
	}
	old, err := os.Open(target)
	if err != nil {
		os.Exit(9)
	}
	backup, err := os.Create(target + ".before-qdt5")
	if err != nil {
		old.Close()
		os.Exit(9)
	}
	_, copyErr := io.Copy(backup, old)
	syncErr := backup.Sync()
	closeErr := backup.Close()
	old.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		os.Exit(9)
	}
	run("sc.exe", "stop", "tacticalrmm")
	for i := 0; i < 60; i++ {
		if err := os.Rename(tmp, target); err == nil {
			run("sc.exe", "start", "tacticalrmm")
			return
		}
		time.Sleep(time.Second)
	}
	run("taskkill.exe", "/F", "/IM", "tacticalrmm.exe")
	time.Sleep(2 * time.Second)
	if err := os.Rename(tmp, target); err != nil {
		run("sc.exe", "start", "tacticalrmm")
		os.Exit(7)
	}
	run("sc.exe", "start", "tacticalrmm")
}
