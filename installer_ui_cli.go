//go:build !fyne

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Janqu/qdt-rmm-agent/agent"
)

func runInstallerUI(a *agent.Agent, opts installerUIOptions) {
	reader := bufio.NewReader(os.Stdin)
	opts.API = promptDefault(reader, "RMM API URL", opts.API)
	opts.Token = promptDefault(reader, "Installer token", opts.Token)
	installFromUI(a, opts)
}

func promptDefault(reader *bufio.Reader, label, current string) string {
	if current != "" {
		fmt.Printf("%s [%s]: ", label, current)
	} else {
		fmt.Printf("%s: ", label)
	}
	value, _ := reader.ReadString('\n')
	value = strings.TrimSpace(value)
	if value == "" {
		return current
	}
	return value
}
