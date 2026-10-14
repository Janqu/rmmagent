package agent

import (
	"regexp"
	"strings"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

func isUSBStorage(instanceID, service, class string) bool {
	upperID := strings.ToUpper(instanceID)
	if strings.HasPrefix(upperID, "USBSTOR\\") {
		return true
	}
	if strings.EqualFold(service, "USBSTOR") {
		return true
	}
	switch strings.ToLower(class) {
	case "usb", "diskdrive", "wpd", "scsiadapter":
		return strings.Contains(upperID, "USBSTOR") || strings.EqualFold(service, "USBSTOR")
	default:
		return false
	}
}

func normalizeUSBRule(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func splitUSBRules(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';'
	})
	out := make([]string, 0, len(fields))
	seen := map[string]struct{}{}
	for _, field := range fields {
		item := normalizeUSBRule(field)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

// usbRuleContains is the exact-match lookup used when adding or removing a
// rule. Policy decisions use usbRuleMatchesAny so wildcards apply.
func usbRuleContains(rules []string, value string) bool {
	needle := normalizeUSBRule(value)
	if needle == "" {
		return false
	}
	for _, rule := range rules {
		if normalizeUSBRule(rule) == needle {
			return true
		}
	}
	return false
}

// usbRuleMatch reports whether one policy rule covers a device identifier.
// Rules are case-insensitive and may use * as a wildcard. A rule without a
// backslash (VID_0951&PID_1666) matches anywhere in the identifier, so a whole
// device model can be allowed without pinning its serial number.
func usbRuleMatch(rule, value string) bool {
	rule, value = normalizeUSBRule(rule), normalizeUSBRule(value)
	if rule == "" || value == "" {
		return false
	}
	if !strings.Contains(rule, `\`) {
		rule = "*" + rule + "*"
	}
	return usbGlobMatch(rule, value)
}

// usbGlobMatch matches pattern against value with * as the only wildcard.
func usbGlobMatch(pattern, value string) bool {
	p, v, star, resume := 0, 0, -1, 0
	for v < len(value) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, p, resume = p, p+1, v
		case p < len(pattern) && pattern[p] == value[v]:
			p, v = p+1, v+1
		case star >= 0:
			p, resume = star+1, resume+1
			v = resume
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

func usbRuleMatchesAny(rules []string, values ...string) bool {
	for _, rule := range rules {
		for _, value := range values {
			if usbRuleMatch(rule, value) {
				return true
			}
		}
	}
	return false
}

// usbDeviceKeys are the identifiers a device rule may match.
func usbDeviceKeys(device rmm.USBDevice) []string {
	keys := []string{device.InstanceID}
	if device.VendorID != "" && device.ProductID != "" {
		keys = append(keys, "VID_"+device.VendorID+"&PID_"+device.ProductID)
	}
	if device.Serial != "" {
		keys = append(keys, device.Serial)
	}
	return keys
}

func usbPolicyAllowsDevice(policy rmm.USBPolicy, device rmm.USBDevice) bool {
	if usbProtectedDevice(device) {
		return true
	}
	keys := usbDeviceKeys(device)
	if usbRuleMatchesAny(policy.BlockedDevices, keys...) {
		return false
	}
	if policy.DefaultAllowed {
		return true
	}
	return usbRuleMatchesAny(policy.AllowedDevices, keys...) ||
		usbRuleMatchesAny(policy.AllowedPorts, device.PortKey, device.Location)
}

var usbIDPattern = regexp.MustCompile(`VID[_]?([0-9A-Fa-f]{4})&?PID[_]?([0-9A-Fa-f]{4})`)

// parseUSBIdentifiers pulls vendor, product and serial out of a Windows
// instance ID such as USB\VID_0951&PID_1666\0012AB34.
func parseUSBIdentifiers(instanceID string) (vendor, product, serial string) {
	if m := usbIDPattern.FindStringSubmatch(instanceID); m != nil {
		vendor, product = strings.ToUpper(m[1]), strings.ToUpper(m[2])
	}
	parts := strings.Split(instanceID, `\`)
	if len(parts) >= 3 {
		last := strings.TrimSpace(parts[len(parts)-1])
		// Composite devices carry an interface index (&0000) instead of a serial.
		if last != "" && !strings.Contains(last, "&") {
			serial = strings.ToUpper(last)
		}
	}
	return vendor, product, serial
}

// usbBooleanValue reads the boolean actions carry in the instance_id field
// (set_policy, set_write_protect).
func usbBooleanValue(value string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "false", "0", "no", "off", "deny", "denied", "block", "blocked":
		return false
	case "true", "1", "yes", "on", "allow", "allowed":
		return true
	default:
		return fallback
	}
}

// diffUSBDevices reports devices that appeared or disappeared between two
// snapshots. A nil previous snapshot seeds the monitor and reports nothing.
func diffUSBDevices(previous, current []rmm.USBDevice) []rmm.USBEvent {
	if previous == nil {
		return nil
	}
	known := make(map[string]struct{}, len(previous))
	for _, device := range previous {
		known[normalizeUSBRule(device.InstanceID)] = struct{}{}
	}
	live := make(map[string]struct{}, len(current))
	events := make([]rmm.USBEvent, 0)
	for _, device := range current {
		key := normalizeUSBRule(device.InstanceID)
		live[key] = struct{}{}
		if _, ok := known[key]; ok {
			continue
		}
		events = append(events, usbEventFor("connected", device))
	}
	for _, device := range previous {
		if _, ok := live[normalizeUSBRule(device.InstanceID)]; !ok {
			events = append(events, usbEventFor("removed", device))
		}
	}
	return events
}

func usbEventFor(action string, device rmm.USBDevice) rmm.USBEvent {
	return rmm.USBEvent{
		Action:       action,
		InstanceID:   device.InstanceID,
		Name:         device.Name,
		VendorID:     device.VendorID,
		ProductID:    device.ProductID,
		Serial:       device.Serial,
		PortKey:      device.PortKey,
		Class:        device.Class,
		Manufacturer: device.Manufacturer,
		Storage:      device.Storage,
		Allowed:      device.PolicyAllowed,
	}
}

// usbProtectedDevice reports devices a policy must never disable, so a rollout
// cannot lock an operator out of their own machine. The decision uses only
// driver-assigned identity — PnP class and service on Windows, interface class
// on Linux — never the device's own descriptor strings: a programmable stick
// can report iProduct "USB Optical Mouse" and would otherwise buy itself a
// blanket exemption. Anything the driver stack reports as mass storage loses
// the exemption even when it also claims an input interface.
func usbProtectedDevice(device rmm.USBDevice) bool {
	if device.Storage || isUSBStorage(device.InstanceID, device.Service, device.Class) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(device.Class)) {
	case "keyboard", "mouse", "hidclass", "hub":
		return true
	}
	// Windows input and hub drivers. usbccgp owns composite devices, so a
	// dock's keyboard stays up while its storage child is judged on its own.
	switch strings.ToLower(strings.TrimSpace(device.Service)) {
	case "kbdhid", "kbdclass", "mouhid", "mouclass", "hidusb", "hidi2c",
		"usbhub", "usbhub3", "usbxhci", "usbccgp":
		return true
	}
	// Unknown identity: older Windows builds answer the WMI query without
	// PNPClass. Fail safe and leave the device alone rather than risk
	// disabling the keyboard of the machine we are managing.
	return device.Class == "" && device.Service == ""
}

func powershellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// applyUSBRuleChange adds or removes one policy rule. Allowing a device drops
// a matching block rule and vice versa, so the two lists cannot contradict.
func applyUSBRuleChange(policy rmm.USBPolicy, action, value string) rmm.USBPolicy {
	switch action {
	case "allow_device":
		policy.AllowedDevices = appendUSBRule(policy.AllowedDevices, value)
		policy.BlockedDevices = removeUSBRule(policy.BlockedDevices, value)
	case "remove_allowed_device":
		policy.AllowedDevices = removeUSBRule(policy.AllowedDevices, value)
	case "block_device":
		policy.BlockedDevices = appendUSBRule(policy.BlockedDevices, value)
		policy.AllowedDevices = removeUSBRule(policy.AllowedDevices, value)
	case "remove_blocked_device":
		policy.BlockedDevices = removeUSBRule(policy.BlockedDevices, value)
	case "allow_port":
		policy.AllowedPorts = appendUSBRule(policy.AllowedPorts, value)
	case "remove_allowed_port":
		policy.AllowedPorts = removeUSBRule(policy.AllowedPorts, value)
	}
	return policy
}

func appendUSBRule(rules []string, value string) []string {
	normalized := normalizeUSBRule(value)
	if normalized == "" || usbRuleContains(rules, normalized) {
		return splitUSBRules(strings.Join(rules, "\n"))
	}
	return append(splitUSBRules(strings.Join(rules, "\n")), normalized)
}

func removeUSBRule(rules []string, value string) []string {
	normalized := normalizeUSBRule(value)
	out := make([]string, 0, len(rules))
	for _, rule := range splitUSBRules(strings.Join(rules, "\n")) {
		if rule != normalized {
			out = append(out, rule)
		}
	}
	return out
}
