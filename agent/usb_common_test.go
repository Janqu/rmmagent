package agent

import (
	"reflect"
	"testing"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
)

func TestIsUSBStorage(t *testing.T) {
	cases := []struct {
		id, service, class string
		want               bool
	}{
		{`USBSTOR\DISK&VEN_KINGSTON`, "USBSTOR", "", true},
		{`USB\VID_0781&PID_5567`, "USBSTOR", "USB", true},
		{`USB\VID_046D&PID_C52B`, "hidusb", "HIDClass", false},
		{`USB\ROOT_HUB30\4&123`, "USBHUB3", "USB", false},
	}
	for _, tc := range cases {
		if got := isUSBStorage(tc.id, tc.service, tc.class); got != tc.want {
			t.Fatalf("%s service=%s class=%s: got %v want %v", tc.id, tc.service, tc.class, got, tc.want)
		}
	}
}

func TestUSBProtectedDevice(t *testing.T) {
	cases := []struct {
		device rmm.USBDevice
		want   bool
	}{
		{rmm.USBDevice{Name: "USB Keyboard", Class: "Keyboard"}, true},
		{rmm.USBDevice{Name: "USB Root Hub", Description: "hub"}, true},
		{rmm.USBDevice{Name: "Kingston DataTraveler", Class: "DiskDrive", Service: "USBSTOR", Storage: true}, false},
		// A stick may name itself anything; only the driver stack is believed.
		{rmm.USBDevice{Name: "USB Optical Mouse", Description: "mouse", Class: "DiskDrive", Service: "USBSTOR", Storage: true}, false},
		{rmm.USBDevice{Name: "Keyboard Hub Storage", InstanceID: `USBSTOR\DISK&VEN_EVIL`, Class: "usb"}, false},
		// Composite HID + mass storage: Linux collapses the class to hidclass.
		{rmm.USBDevice{Name: "Rubber Ducky", Class: "hidclass", Service: "usbcore", Storage: true}, false},
		// Real input hardware keeps working, including on degraded WMI queries
		// that answer without PNPClass, and behind the composite parent driver.
		{rmm.USBDevice{Name: "Logitech Unifying Receiver", Class: "", Service: ""}, true},
		{rmm.USBDevice{Name: "Dell Dock", Class: "USB", Service: "usbccgp"}, true},
		{rmm.USBDevice{Name: "HID Keyboard Device", Class: "HIDClass", Service: "kbdhid"}, true},
		{rmm.USBDevice{Name: "Generic Serial Adapter", Class: "Ports", Service: "usbser"}, false},
	}
	for _, tc := range cases {
		if got := usbProtectedDevice(tc.device); got != tc.want {
			t.Fatalf("%+v: got %v want %v", tc.device, got, tc.want)
		}
	}
}

func TestUSBPolicyAllowsDevice(t *testing.T) {
	keyboard := rmm.USBDevice{Name: "USB Keyboard", Class: "Keyboard", InstanceID: `USB\VID_KBD`}
	stick := rmm.USBDevice{Name: "Kingston", InstanceID: `USBSTOR\DISK&VEN_KINGSTON`, PortKey: `PORT_#0002`, Storage: true}

	if !usbPolicyAllowsDevice(rmm.USBPolicy{DefaultAllowed: true}, stick) {
		t.Fatal("default allowed policy should allow USB devices")
	}
	if usbPolicyAllowsDevice(rmm.USBPolicy{DefaultAllowed: true, BlockedDevices: []string{`USBSTOR\DISK&VEN_KINGSTON`}}, stick) {
		t.Fatal("explicit block should win while default allowed")
	}
	if usbPolicyAllowsDevice(rmm.USBPolicy{}, stick) {
		t.Fatal("default denied policy should block unknown devices")
	}
	if !usbPolicyAllowsDevice(rmm.USBPolicy{AllowedPorts: []string{`port_#0002`}}, stick) {
		t.Fatal("allowed port should allow a default denied device")
	}
	if !usbPolicyAllowsDevice(rmm.USBPolicy{}, keyboard) {
		t.Fatal("protected input devices should stay allowed")
	}

	// Descriptor strings must not buy a storage device an exemption.
	spoofed := rmm.USBDevice{Name: "USB Optical Mouse", Description: "mouse",
		InstanceID: `USBSTOR\DISK&VEN_EVIL`, Class: "DiskDrive", Service: "USBSTOR", Storage: true}
	if usbPolicyAllowsDevice(rmm.USBPolicy{}, spoofed) {
		t.Fatal("storage device naming itself a mouse must stay blocked under default deny")
	}
	if usbPolicyAllowsDevice(rmm.USBPolicy{DefaultAllowed: true, BlockedDevices: []string{`USBSTOR\DISK&VEN_EVIL`}}, spoofed) {
		t.Fatal("storage device naming itself a mouse must not escape an explicit block")
	}
}

func TestPowershellQuote(t *testing.T) {
	if got := powershellQuote(`USB\VID_1234&PID_5678`); got != `'USB\VID_1234&PID_5678'` {
		t.Fatalf("got %q", got)
	}
	if got := powershellQuote(`O'Brien`); got != `'O''Brien'` {
		t.Fatalf("got %q", got)
	}
}

func TestUSBRuleMatch(t *testing.T) {
	cases := []struct {
		rule, value string
		want        bool
	}{
		// A model rule keeps working when the stick is swapped for the same model.
		{`VID_0951&PID_1666`, `USB\VID_0951&PID_1666\0012AB34`, true},
		{`VID_0951&PID_1666`, `USB\VID_0951&PID_1667\0012AB34`, false},
		{`USB\VID_0951&PID_1666*`, `USB\VID_0951&PID_1666\0012AB34`, true},
		{`USB\VID_0951&PID_1666\*`, `USB\VID_0951&PID_1666`, false},
		{`usb\vid_0951*`, `USB\VID_0951&PID_1666\0012AB34`, true},
		{`USB\VID_0951&PID_1666\0012AB34`, `USB\VID_0951&PID_1666\0012AB34`, true},
		{`USB\VID_0951&PID_1666\0012AB34`, `USB\VID_0951&PID_1666\0012AB35`, false},
		{`*KINGSTON*`, `USBSTOR\DISK&VEN_KINGSTON&PROD_DT`, true},
		{``, `USB\VID_0951`, false},
		{`VID_0951`, ``, false},
	}
	for _, tc := range cases {
		if got := usbRuleMatch(tc.rule, tc.value); got != tc.want {
			t.Fatalf("rule %q value %q: got %v want %v", tc.rule, tc.value, got, tc.want)
		}
	}
}

func TestUSBPolicyWildcardRules(t *testing.T) {
	stick := rmm.USBDevice{
		Name: "Kingston", InstanceID: `USB\VID_0951&PID_1666\0012AB34`,
		VendorID: "0951", ProductID: "1666", Serial: "0012AB34",
		PortKey: "1-4", Storage: true,
	}
	if !usbPolicyAllowsDevice(rmm.USBPolicy{AllowedDevices: []string{`VID_0951&PID_1666`}}, stick) {
		t.Fatal("model rule should allow the device while default denied")
	}
	if usbPolicyAllowsDevice(rmm.USBPolicy{DefaultAllowed: true, BlockedDevices: []string{`VID_0951&PID_*`}}, stick) {
		t.Fatal("wildcard block rule should win over default allowed")
	}
	other := stick
	other.InstanceID = `USB\VID_0951&PID_1666\9999ZZ99`
	other.Serial = "9999ZZ99"
	if !usbPolicyAllowsDevice(rmm.USBPolicy{AllowedDevices: []string{`VID_0951&PID_1666`}}, other) {
		t.Fatal("replacement stick of the same model should stay allowed")
	}
}

func TestParseUSBIdentifiers(t *testing.T) {
	vendor, product, serial := parseUSBIdentifiers(`USB\VID_0951&PID_1666\0012ab34`)
	if vendor != "0951" || product != "1666" || serial != "0012AB34" {
		t.Fatalf("got %q %q %q", vendor, product, serial)
	}
	// Composite interfaces carry an index, not a serial.
	if _, _, serial := parseUSBIdentifiers(`USB\VID_046D&PID_C52B\6&2A1C8D1&0&1`); serial != "" {
		t.Fatalf("got serial %q", serial)
	}
	if vendor, product, _ := parseUSBIdentifiers(`SWD\PRINTENUM\LOCALHOST`); vendor != "" || product != "" {
		t.Fatalf("got %q %q", vendor, product)
	}
}

func TestUSBBooleanValue(t *testing.T) {
	for value, want := range map[string]bool{"true": true, "1": true, "false": false, "0": false, "blocked": false, "": true} {
		if got := usbBooleanValue(value, true); got != want {
			t.Fatalf("%q: got %v want %v", value, got, want)
		}
	}
	if usbBooleanValue("", false) {
		t.Fatal("empty value must keep the fallback")
	}
}

func TestDiffUSBDevices(t *testing.T) {
	stick := rmm.USBDevice{Name: "Kingston", InstanceID: `USB\VID_0951&PID_1666\A`, Storage: true}
	mouse := rmm.USBDevice{Name: "Mouse", InstanceID: `USB\VID_046D&PID_C52B\B`, PolicyAllowed: true}

	if events := diffUSBDevices(nil, []rmm.USBDevice{stick}); len(events) != 0 {
		t.Fatalf("first poll must only seed, got %d events", len(events))
	}
	events := diffUSBDevices([]rmm.USBDevice{mouse}, []rmm.USBDevice{mouse, stick})
	if len(events) != 1 || events[0].Action != "connected" || events[0].InstanceID != stick.InstanceID || events[0].Allowed {
		t.Fatalf("got %+v", events)
	}
	events = diffUSBDevices([]rmm.USBDevice{mouse, stick}, []rmm.USBDevice{mouse})
	if len(events) != 1 || events[0].Action != "removed" || events[0].InstanceID != stick.InstanceID {
		t.Fatalf("got %+v", events)
	}
	if events := diffUSBDevices([]rmm.USBDevice{mouse}, []rmm.USBDevice{mouse}); len(events) != 0 {
		t.Fatalf("got %+v", events)
	}
}

func TestApplyUSBRuleChange(t *testing.T) {
	policy := applyUSBRuleChange(rmm.USBPolicy{}, "block_device", `vid_0951&pid_1666`)
	if !reflect.DeepEqual(policy.BlockedDevices, []string{"VID_0951&PID_1666"}) {
		t.Fatalf("got %+v", policy.BlockedDevices)
	}
	policy = applyUSBRuleChange(policy, "allow_device", `VID_0951&PID_1666`)
	if len(policy.BlockedDevices) != 0 || !reflect.DeepEqual(policy.AllowedDevices, []string{"VID_0951&PID_1666"}) {
		t.Fatalf("allow must drop the contradicting block: %+v", policy)
	}
	policy = applyUSBRuleChange(policy, "allow_device", `VID_0951&PID_1666`)
	if len(policy.AllowedDevices) != 1 {
		t.Fatalf("duplicate rule: %+v", policy.AllowedDevices)
	}
	policy = applyUSBRuleChange(policy, "remove_allowed_device", `VID_0951&PID_1666`)
	if len(policy.AllowedDevices) != 0 {
		t.Fatalf("got %+v", policy.AllowedDevices)
	}
	policy = applyUSBRuleChange(policy, "allow_port", "1-4")
	if !reflect.DeepEqual(policy.AllowedPorts, []string{"1-4"}) {
		t.Fatalf("got %+v", policy.AllowedPorts)
	}
	if got := applyUSBRuleChange(policy, "remove_allowed_port", "1-4"); len(got.AllowedPorts) != 0 {
		t.Fatalf("got %+v", got.AllowedPorts)
	}
}
