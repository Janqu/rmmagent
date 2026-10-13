//go:build fyne

package main

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/Janqu/qdt-rmm-agent/agent"
)

func runInstallerUI(a *agent.Agent, opts installerUIOptions) {
	ui := app.New()
	window := ui.NewWindow("QDT RMM Agent Installer")

	apiEntry := widget.NewEntry()
	apiEntry.SetPlaceHolder("https://rmm.example.com")
	apiEntry.SetText(opts.API)

	tokenEntry := widget.NewPasswordEntry()
	tokenEntry.SetPlaceHolder("Installer token from RMM")
	tokenEntry.SetText(opts.Token)

	status := widget.NewLabel("")
	installButton := widget.NewButton("Install", nil)
	installButton.Disable()
	checkButton := widget.NewButton("Check token", nil)
	pasteButton := widget.NewButton("Paste token", func() {
		if token := strings.TrimSpace(ui.Clipboard().Content()); token != "" {
			tokenEntry.SetText(token)
		}
	})

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "RMM API URL", Widget: apiEntry},
			{Text: "Installer token", Widget: tokenEntry},
		},
	}
	apiEntry.OnChanged = func(string) { installButton.Disable() }
	tokenEntry.OnChanged = func(string) { installButton.Disable() }

	checkButton.OnTapped = func() {
		opts.API = strings.TrimSpace(apiEntry.Text)
		opts.Token = strings.TrimSpace(tokenEntry.Text)
		if opts.API == "" || opts.Token == "" {
			dialog.ShowError(errInstallerFieldsRequired{}, window)
			return
		}
		checkButton.Disable()
		installButton.Disable()
		status.SetText("Checking token...")
		go func() {
			info, err := fetchInstallerTokenInfo(opts.API, opts.Token, opts.Insecure)
			fyne.Do(func() {
				checkButton.Enable()
				if err != nil {
					status.SetText("Token check failed")
					dialog.ShowError(err, window)
					return
				}
				status.SetText(installerInfoText(info))
				installButton.Enable()
			})
		}()
	}

	installButton.OnTapped = func() {
		opts.API = strings.TrimSpace(apiEntry.Text)
		opts.Token = strings.TrimSpace(tokenEntry.Text)
		if opts.API == "" || opts.Token == "" {
			dialog.ShowError(errInstallerFieldsRequired{}, window)
			return
		}
		checkButton.Disable()
		installButton.Disable()
		status.SetText("Installing...")
		go func() {
			output, err := runInstallerCommand(opts)
			fyne.Do(func() {
				if err != nil {
					checkButton.Enable()
					installButton.Enable()
					status.SetText("Installation failed")
					dialog.ShowError(fmt.Errorf("%v\n%s", err, strings.TrimSpace(output)), window)
					return
				}
				status.SetText("Installation completed")
				dialog.ShowInformation("Installation completed", "The agent was installed successfully.", window)
			})
		}()
	}

	window.SetContent(container.NewVBox(form, container.NewHBox(pasteButton, checkButton, installButton), status))
	window.Resize(fyne.NewSize(480, 220))
	window.ShowAndRun()
}

func installerInfoText(info installerTokenInfo) string {
	options := []string{}
	if info.Power {
		options = append(options, "power")
	}
	if info.RDP {
		options = append(options, "rdp")
	}
	if info.Ping {
		options = append(options, "ping")
	}
	if len(options) == 0 {
		return fmt.Sprintf("Token OK: site %d, %s", info.Site, info.MonitoringType)
	}
	return fmt.Sprintf("Token OK: site %d, %s, options: %s", info.Site, info.MonitoringType, strings.Join(options, ", "))
}

type errInstallerFieldsRequired struct{}

func (errInstallerFieldsRequired) Error() string {
	return "RMM API URL and installer token are required."
}
