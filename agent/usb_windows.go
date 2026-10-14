//go:build windows

package agent

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
	"github.com/StackExchange/wmi"
	"golang.org/x/sys/windows/registry"
)

const (
	usbStorServicePath       = `SYSTEM\CurrentControlSet\Services\USBSTOR`
	usbStoragePoliciesPath   = `SYSTEM\CurrentControlSet\Control\StorageDevicePolicies`
	usbWriteProtectValueName = "WriteProtect"
	cmProbDisabled           = 22
)

type win32PnPEntityUSB struct {
	Name                   string
	DeviceID               string
	PNPDeviceID            string
	Status                 string
	ConfigManagerErrorCode uint32
	Description            string
	Manufacturer           string
	Service                string
	PNPClass               string
	LocationInformation    string
}

func (a *Agent) ListUSBDevices() rmm.USBListResp {
	policy := readUSBPolicy()
	devices := listUSBPnPDevices(policy)
	return rmm.USBListResp{
		Devices:          devices,
		StorageBlocked:   usbStorageBlocked(),
		WriteProtect:     usbWriteProtected(),
		WriteProtectable: true,
		Policy:           policy,
	}
}

func (a *Agent) USBAction(action, instanceID, scope string) rmm.WinSvcResp {
	action = strings.ToLower(strings.TrimSpace(action))
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope == "" {
		scope = "storage"
	}
	switch action {
	case "disable", "enable":
		instanceID = strings.TrimSpace(instanceID)
		if instanceID == "" {
			return rmm.WinSvcResp{Success: false, ErrorMsg: "instance_id is required"}
		}
		if err := setPnPDeviceEnabled(instanceID, action == "enable"); err != nil {
			return rmm.WinSvcResp{Success: false, ErrorMsg: err.Error()}
		}
		return rmm.WinSvcResp{Success: true}
	case "allow_device", "block_device":
		instanceID = strings.TrimSpace(instanceID)
		if instanceID == "" {
			return rmm.WinSvcResp{Success: false, ErrorMsg: "instance_id is required"}
		}
		if err := updateUSBPolicyRules(action, instanceID); err != nil {
			return rmm.WinSvcResp{Success: false, ErrorMsg: err.Error()}
		}
		return applyUSBPolicy()
	case "allow_port", "remove_allowed_port":
		portKey := strings.TrimSpace(instanceID)
		if portKey == "" {
			return rmm.WinSvcResp{Success: false, ErrorMsg: "port_key is required"}
		}
		if err := updateUSBPolicyRules(action, portKey); err != nil {
			return rmm.WinSvcResp{Success: false, ErrorMsg: err.Error()}
		}
		return applyUSBPolicy()
	case "remove_allowed_device", "remove_blocked_device":
		instanceID = strings.TrimSpace(instanceID)
		if instanceID == "" {
			return rmm.WinSvcResp{Success: false, ErrorMsg: "instance_id is required"}
		}
		if err := updateUSBPolicyRules(action, instanceID); err != nil {
			return rmm.WinSvcResp{Success: false, ErrorMsg: err.Error()}
		}
		return applyUSBPolicy()
	case "set_policy":
		policy := readUSBPolicy()
		policy.DefaultAllowed = usbBooleanValue(instanceID, true)
		if err := writeUSBPolicy(policy); err != nil {
			return rmm.WinSvcResp{Success: false, ErrorMsg: err.Error()}
		}
		return applyUSBPolicy()
	case "set_write_protect":
		policy := readUSBPolicy()
		policy.WriteProtect = usbBooleanValue(instanceID, false)
		if err := writeUSBPolicy(policy); err != nil {
			return rmm.WinSvcResp{Success: false, ErrorMsg: err.Error()}
		}
		return applyUSBPolicy()
	case "disable_all", "enable_all":
		policy := readUSBPolicy()
		policy.DefaultAllowed = action == "enable_all"
		if err := writeUSBPolicy(policy); err != nil {
			return rmm.WinSvcResp{Success: false, ErrorMsg: err.Error()}
		}
		return applyUSBPolicy()
	case "enforce":
		return applyUSBPolicy()
	default:
		return rmm.WinSvcResp{Success: false, ErrorMsg: "unsupported action"}
	}
}

func applyUSBPolicy() rmm.WinSvcResp {
	policy := readUSBPolicy()
	// Default-deny without a single per-device or per-port exception: stop the
	// mass-storage class driver itself, so a stick inserted between two monitor
	// ticks never mounts. This touches USBSTOR only — keyboards, mice, hubs and
	// every other device class keep working, so it cannot lock anyone out. Once
	// an allow rule exists the driver has to stay loaded for that device to
	// work, and enforcement falls back to disabling devices one by one.
	blockStorage := !policy.DefaultAllowed && len(policy.AllowedDevices) == 0 && len(policy.AllowedPorts) == 0
	if err := setUSBStorageBlocked(blockStorage); err != nil {
		return rmm.WinSvcResp{Success: false, ErrorMsg: err.Error()}
	}
	_ = setUSBStorageDesired(!policy.DefaultAllowed)
	devices := listUSBPnPDevices(policy)
	var failed []string
	// The stored policy is the source of truth: enforcing with write
	// protection off also clears a WriteProtect set outside the RMM.
	if err := setUSBWriteProtected(policy.WriteProtect); err != nil {
		failed = append(failed, fmt.Sprintf("write protect: %v", err))
	}
	for _, device := range devices {
		shouldEnable := usbPolicyAllowsDevice(policy, device)
		if device.Enabled == shouldEnable {
			continue
		}
		if err := setPnPDeviceEnabled(device.InstanceID, shouldEnable); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", device.Name, err))
		}
	}
	if len(failed) > 0 {
		return rmm.WinSvcResp{Success: false, ErrorMsg: strings.Join(failed, "; ")}
	}
	return rmm.WinSvcResp{Success: true}
}

// EnforceUSBStoragePolicy reapplies the stored USB policy after agent start.
func (a *Agent) EnforceUSBStoragePolicy() {
	if !usbPolicyConfigured() {
		return
	}
	resp := a.USBAction("enforce", "", "storage")
	if !resp.Success {
		a.Logger.Errorln("EnforceUSBStoragePolicy:", resp.ErrorMsg)
	}
}

// usbPolicyConfigured reports whether an operator ever set a USB policy, so a
// never-managed machine is left untouched at startup.
func usbPolicyConfigured() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, usbPolicyKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	for _, name := range []string{usbStorageDesiredValue, usbPolicyDefaultAllowed, usbPolicyWriteProtect} {
		if _, _, err := k.GetIntegerValue(name); err == nil {
			return true
		}
	}
	for _, name := range []string{usbPolicyAllowedDevices, usbPolicyAllowedPorts, usbPolicyBlockedDevices} {
		if values, _, err := k.GetStringsValue(name); err == nil && len(values) > 0 {
			return true
		}
	}
	return false
}

func listUSBPnPDevices(policy rmm.USBPolicy) []rmm.USBDevice {
	var rows []win32PnPEntityUSB
	query := "SELECT Name, DeviceID, PNPDeviceID, Status, ConfigManagerErrorCode, Description, Manufacturer, Service, PNPClass, LocationInformation FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB%' OR PNPDeviceID LIKE 'USBSTOR%'"
	if err := wmi.Query(query, &rows); err != nil {
		// Older Windows builds may lack PNPClass.
		query = "SELECT Name, DeviceID, PNPDeviceID, Status, ConfigManagerErrorCode, Description, Manufacturer, Service FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB%' OR PNPDeviceID LIKE 'USBSTOR%'"
		if err := wmi.Query(query, &rows); err != nil {
			return nil
		}
	}
	out := make([]rmm.USBDevice, 0, len(rows))
	seen := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		instanceID := firstNonEmpty(row.DeviceID, row.PNPDeviceID)
		if instanceID == "" {
			continue
		}
		key := strings.ToUpper(instanceID)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		class := strings.TrimSpace(row.PNPClass)
		service := strings.TrimSpace(row.Service)
		storage := isUSBStorage(instanceID, service, class)
		enabled := row.ConfigManagerErrorCode != cmProbDisabled
		status := strings.TrimSpace(row.Status)
		if !enabled {
			status = "Disabled"
		}
		location := strings.TrimSpace(row.LocationInformation)
		portKey := firstNonEmpty(location, instanceID)
		vendor, product, serial := parseUSBIdentifiers(instanceID)
		device := rmm.USBDevice{
			Name:         firstNonEmpty(row.Name, row.Description, instanceID),
			InstanceID:   instanceID,
			Location:     location,
			PortKey:      portKey,
			Status:       status,
			Manufacturer: strings.TrimSpace(row.Manufacturer),
			Description:  strings.TrimSpace(row.Description),
			Class:        class,
			Service:      service,
			VendorID:     vendor,
			ProductID:    product,
			Serial:       serial,
			Storage:      storage,
			Enabled:      enabled,
		}
		device.PolicyAllowed = usbPolicyAllowsDevice(policy, device)
		device.PolicyBlocked = usbRuleMatchesAny(policy.BlockedDevices, usbDeviceKeys(device)...) || (!policy.DefaultAllowed && !device.PolicyAllowed)
		out = append(out, device)
	}
	return out
}

func usbStorageBlocked() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, usbStorServicePath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	start, _, err := k.GetIntegerValue("Start")
	if err != nil {
		return false
	}
	return start == 4
}

func setUSBStorageBlocked(blocked bool) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, usbStorServicePath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open USBSTOR service key: %w", err)
	}
	defer k.Close()
	start := uint32(3)
	if blocked {
		start = 4
	}
	return k.SetDWordValue("Start", start)
}

// usbWriteProtected reports the StorageDevicePolicies write protection that
// leaves USB storage readable but not writable.
func usbWriteProtected() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, usbStoragePoliciesPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	value, _, err := k.GetIntegerValue(usbWriteProtectValueName)
	if err != nil {
		return false
	}
	return value == 1
}

func setUSBWriteProtected(enabled bool) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, usbStoragePoliciesPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open StorageDevicePolicies key: %w", err)
	}
	defer k.Close()
	value := uint32(0)
	if enabled {
		value = 1
	}
	return k.SetDWordValue(usbWriteProtectValueName, value)
}

const usbStorageDesiredValue = "UsbStorageBlocked"
const usbPolicyKey = `SOFTWARE\TacticalRMM`
const usbPolicyDefaultAllowed = "UsbDefaultAllowed"
const usbPolicyAllowedDevices = "UsbAllowedDevices"
const usbPolicyAllowedPorts = "UsbAllowedPorts"
const usbPolicyBlockedDevices = "UsbBlockedDevices"
const usbPolicyWriteProtect = "UsbWriteProtect"

func setUSBStorageDesired(blocked bool) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, usbPolicyKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	value := uint32(0)
	if blocked {
		value = 1
	}
	return k.SetDWordValue(usbStorageDesiredValue, value)
}

func readUSBPolicy() rmm.USBPolicy {
	policy := rmm.USBPolicy{DefaultAllowed: true}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, usbPolicyKey, registry.QUERY_VALUE)
	if err != nil {
		return policy
	}
	defer k.Close()
	if value, _, err := k.GetIntegerValue(usbPolicyDefaultAllowed); err == nil {
		policy.DefaultAllowed = value != 0
	}
	if value, _, err := k.GetIntegerValue(usbPolicyWriteProtect); err == nil {
		policy.WriteProtect = value != 0
	}
	policy.AllowedDevices = readUSBPolicyStrings(k, usbPolicyAllowedDevices)
	policy.AllowedPorts = readUSBPolicyStrings(k, usbPolicyAllowedPorts)
	policy.BlockedDevices = readUSBPolicyStrings(k, usbPolicyBlockedDevices)
	return policy
}

func readUSBPolicyStrings(k registry.Key, name string) []string {
	values, _, err := k.GetStringsValue(name)
	if err != nil {
		return nil
	}
	return splitUSBRules(strings.Join(values, "\n"))
}

func writeUSBPolicy(policy rmm.USBPolicy) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, usbPolicyKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	defaultAllowed := uint32(0)
	if policy.DefaultAllowed {
		defaultAllowed = 1
	}
	if err := k.SetDWordValue(usbPolicyDefaultAllowed, defaultAllowed); err != nil {
		return err
	}
	writeProtect := uint32(0)
	if policy.WriteProtect {
		writeProtect = 1
	}
	if err := k.SetDWordValue(usbPolicyWriteProtect, writeProtect); err != nil {
		return err
	}
	if err := k.SetStringsValue(usbPolicyAllowedDevices, splitUSBRules(strings.Join(policy.AllowedDevices, "\n"))); err != nil {
		return err
	}
	if err := k.SetStringsValue(usbPolicyAllowedPorts, splitUSBRules(strings.Join(policy.AllowedPorts, "\n"))); err != nil {
		return err
	}
	return k.SetStringsValue(usbPolicyBlockedDevices, splitUSBRules(strings.Join(policy.BlockedDevices, "\n")))
}

func updateUSBPolicyRules(action, value string) error {
	return writeUSBPolicy(applyUSBRuleChange(readUSBPolicy(), action, value))
}

func setPnPDeviceEnabled(instanceID string, enable bool) error {
	flag := "/disable-device"
	if enable {
		flag = "/enable-device"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "pnputil.exe", flag, instanceID)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	psAction := "Disable-PnpDevice"
	if enable {
		psAction = "Enable-PnpDevice"
	}
	script := fmt.Sprintf(
		"%s -InstanceId %s -Confirm:$false -ErrorAction Stop",
		psAction,
		powershellQuote(instanceID),
	)
	ps := exec.CommandContext(ctx, getPowershellExe(), "-NonInteractive", "-NoProfile", "-Command", script)
	psOut, psErr := ps.CombinedOutput()
	if psErr != nil {
		msg := strings.TrimSpace(string(psOut))
		if msg == "" {
			msg = strings.TrimSpace(string(out))
		}
		if msg == "" {
			msg = psErr.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}
