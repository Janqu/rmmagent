//go:build linux

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

const (
	usbClassHID    = "03"
	usbClassMass   = "08"
	usbClassHub    = "09"
	usbAuthorized  = "authorized"
	usbPolicyPerms = 0o600
)

// Overridden in tests.
var (
	// usbSysfsRoot holds one directory per USB device (1-4) and per interface
	// (1-4:1.0). Writing 0 to authorized makes the kernel detach the device.
	usbSysfsRoot  = "/sys/bus/usb/devices"
	usbPolicyFile = "/etc/tacticalagent-usb-policy.json"
)

// usbLinuxDevice pairs the reported device with its sysfs directory, which is
// what enable/disable writes to.
type usbLinuxDevice struct {
	rmm.USBDevice
	path string
}

func (a *Agent) ListUSBDevices() rmm.USBListResp {
	policy := readUSBPolicy()
	devices := listUSBSysfsDevices(policy)
	out := make([]rmm.USBDevice, 0, len(devices))
	for _, device := range devices {
		out = append(out, device.USBDevice)
	}
	return rmm.USBListResp{Devices: out, Policy: policy}
}

func (a *Agent) USBAction(action, instanceID, scope string) rmm.WinSvcResp {
	action = strings.ToLower(strings.TrimSpace(action))
	instanceID = strings.TrimSpace(instanceID)
	switch action {
	case "enable", "disable":
		if instanceID == "" {
			return rmm.WinSvcResp{Success: false, ErrorMsg: "instance_id is required"}
		}
		device, ok := findUSBSysfsDevice(instanceID)
		if !ok {
			return rmm.WinSvcResp{Success: false, ErrorMsg: "USB device " + instanceID + " was not found"}
		}
		if err := setUSBSysfsAuthorized(device.path, action == "enable"); err != nil {
			return rmm.WinSvcResp{Success: false, ErrorMsg: err.Error()}
		}
		return rmm.WinSvcResp{Success: true}
	case "allow_device", "block_device", "remove_allowed_device", "remove_blocked_device", "allow_port", "remove_allowed_port":
		if instanceID == "" {
			return rmm.WinSvcResp{Success: false, ErrorMsg: "instance_id is required"}
		}
		if err := writeUSBPolicy(applyUSBRuleChange(readUSBPolicy(), action, instanceID)); err != nil {
			return rmm.WinSvcResp{Success: false, ErrorMsg: err.Error()}
		}
		return applyUSBPolicy()
	case "set_policy", "enable_all", "disable_all":
		policy := readUSBPolicy()
		if action == "set_policy" {
			policy.DefaultAllowed = usbBooleanValue(instanceID, true)
		} else {
			policy.DefaultAllowed = action == "enable_all"
		}
		if err := writeUSBPolicy(policy); err != nil {
			return rmm.WinSvcResp{Success: false, ErrorMsg: err.Error()}
		}
		return applyUSBPolicy()
	case "set_write_protect":
		return rmm.WinSvcResp{Success: false, ErrorMsg: "USB write protection is only supported on Windows agents"}
	case "enforce":
		return applyUSBPolicy()
	default:
		return rmm.WinSvcResp{Success: false, ErrorMsg: "unsupported action"}
	}
}

// EnforceUSBStoragePolicy reapplies the stored policy after agent start. sysfs
// authorization does not survive a reboot, so this restores it.
func (a *Agent) EnforceUSBStoragePolicy() {
	if _, err := os.Stat(usbPolicyFile); err != nil {
		return
	}
	if resp := applyUSBPolicy(); !resp.Success {
		a.Logger.Errorln("EnforceUSBStoragePolicy:", resp.ErrorMsg)
	}
}

func applyUSBPolicy() rmm.WinSvcResp {
	policy := readUSBPolicy()
	var failed []string
	for _, device := range listUSBSysfsDevices(policy) {
		shouldEnable := usbPolicyAllowsDevice(policy, device.USBDevice)
		if device.Enabled == shouldEnable {
			continue
		}
		if err := setUSBSysfsAuthorized(device.path, shouldEnable); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", device.Name, err))
		}
	}
	if len(failed) > 0 {
		return rmm.WinSvcResp{Success: false, ErrorMsg: strings.Join(failed, "; ")}
	}
	return rmm.WinSvcResp{Success: true}
}

func listUSBSysfsDevices(policy rmm.USBPolicy) []usbLinuxDevice {
	entries, err := os.ReadDir(usbSysfsRoot)
	if err != nil {
		return nil
	}
	out := make([]usbLinuxDevice, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		// Interface directories (1-4:1.0) describe an already listed device.
		if strings.Contains(name, ":") {
			continue
		}
		path := filepath.Join(usbSysfsRoot, name)
		device, ok := readUSBSysfsDevice(path, name)
		if !ok {
			continue
		}
		device.PolicyAllowed = usbPolicyAllowsDevice(policy, device.USBDevice)
		device.PolicyBlocked = usbRuleMatchesAny(policy.BlockedDevices, usbDeviceKeys(device.USBDevice)...) ||
			(!policy.DefaultAllowed && !device.PolicyAllowed)
		out = append(out, device)
	}
	return out
}

// readUSBSysfsDevice reads one /sys/bus/usb/devices entry. Entries without a
// vendor/product pair are buses, not devices.
func readUSBSysfsDevice(path, name string) (usbLinuxDevice, bool) {
	vendor := readUSBSysfsAttr(path, "idVendor")
	product := readUSBSysfsAttr(path, "idProduct")
	if vendor == "" || product == "" {
		return usbLinuxDevice{}, false
	}
	device := usbLinuxDevice{path: path}
	device.VendorID = strings.ToUpper(vendor)
	device.ProductID = strings.ToUpper(product)
	device.Serial = strings.ToUpper(readUSBSysfsAttr(path, "serial"))
	device.Location = name
	device.PortKey = name
	device.Manufacturer = readUSBSysfsAttr(path, "manufacturer")
	device.Description = readUSBSysfsAttr(path, "product")
	device.Name = firstNonEmptyUSB(device.Description, device.Manufacturer, name)
	device.InstanceID = usbLinuxInstanceID(device.VendorID, device.ProductID, device.Serial, name)
	classes := usbSysfsClasses(path, name)
	device.Class = usbLinuxClassName(classes)
	device.Service = "usbcore"
	device.Storage = usbClassSetContains(classes, usbClassMass)
	device.Enabled = readUSBSysfsAttr(path, usbAuthorized) != "0"
	device.Status = "OK"
	if !device.Enabled {
		device.Status = "Disabled"
	}
	return device, true
}

func findUSBSysfsDevice(instanceID string) (usbLinuxDevice, bool) {
	needle := normalizeUSBRule(instanceID)
	for _, device := range listUSBSysfsDevices(rmm.USBPolicy{DefaultAllowed: true}) {
		if normalizeUSBRule(device.InstanceID) == needle || normalizeUSBRule(device.Location) == needle {
			return device, true
		}
	}
	return usbLinuxDevice{}, false
}

// usbLinuxInstanceID keeps the Windows instance ID shape so one policy rule
// matches the same hardware on either platform.
func usbLinuxInstanceID(vendor, product, serial, busID string) string {
	tail := serial
	if tail == "" {
		tail = strings.ToUpper(busID)
	}
	return `USB\VID_` + vendor + `&PID_` + product + `\` + tail
}

// usbSysfsClasses collects the device class plus every interface class, since
// a composite device reports class 00 on the device itself.
func usbSysfsClasses(path, name string) []string {
	classes := make([]string, 0, 4)
	if class := readUSBSysfsAttr(path, "bDeviceClass"); class != "" {
		classes = append(classes, strings.ToLower(class))
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return classes
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), name+":") {
			continue
		}
		class := readUSBSysfsAttr(filepath.Join(path, entry.Name()), "bInterfaceClass")
		if class != "" {
			classes = append(classes, strings.ToLower(class))
		}
	}
	return classes
}

func usbClassSetContains(classes []string, want string) bool {
	for _, class := range classes {
		if class == want {
			return true
		}
	}
	return false
}

// usbLinuxClassName maps USB class codes onto the class labels the shared
// policy helpers already understand from Windows.
func usbLinuxClassName(classes []string) string {
	switch {
	case usbClassSetContains(classes, usbClassHub):
		return "hub"
	case usbClassSetContains(classes, usbClassHID):
		return "hidclass"
	case usbClassSetContains(classes, usbClassMass):
		return "diskdrive"
	default:
		return "usb"
	}
}

func readUSBSysfsAttr(path, name string) string {
	data, err := os.ReadFile(filepath.Join(path, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func setUSBSysfsAuthorized(path string, enable bool) error {
	value := []byte("0")
	if enable {
		value = []byte("1")
	}
	target := filepath.Join(path, usbAuthorized)
	if err := os.WriteFile(target, value, 0o200); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	return nil
}

func readUSBPolicy() rmm.USBPolicy {
	data, err := os.ReadFile(usbPolicyFile)
	if err != nil {
		return rmm.USBPolicy{DefaultAllowed: true}
	}
	policy := rmm.USBPolicy{DefaultAllowed: true}
	if json.Unmarshal(data, &policy) != nil {
		return rmm.USBPolicy{DefaultAllowed: true}
	}
	return normalizeUSBPolicy(policy)
}

func writeUSBPolicy(policy rmm.USBPolicy) error {
	data, err := json.Marshal(normalizeUSBPolicy(policy))
	if err != nil {
		return err
	}
	return os.WriteFile(usbPolicyFile, data, usbPolicyPerms)
}

// normalizeUSBPolicy de-duplicates the rule lists. Write protection has no
// Linux equivalent, so it is never stored.
func normalizeUSBPolicy(policy rmm.USBPolicy) rmm.USBPolicy {
	policy.AllowedDevices = splitUSBRules(strings.Join(policy.AllowedDevices, "\n"))
	policy.AllowedPorts = splitUSBRules(strings.Join(policy.AllowedPorts, "\n"))
	policy.BlockedDevices = splitUSBRules(strings.Join(policy.BlockedDevices, "\n"))
	policy.WriteProtect = false
	return policy
}

// firstNonEmptyUSB mirrors firstNonEmpty, which is Windows only.
func firstNonEmptyUSB(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
