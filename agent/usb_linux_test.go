//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"testing"

	rmm "github.com/Janqu/qdt-rmm-agent/shared"
	"github.com/sirupsen/logrus"
)

// fakeSysfsDevice writes the attributes the lister reads for one device.
func fakeSysfsDevice(t *testing.T, root, name string, attrs map[string]string, interfaceClasses ...string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for key, value := range attrs {
		if err := os.WriteFile(filepath.Join(dir, key), []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for i, class := range interfaceClasses {
		iface := filepath.Join(dir, name+":1."+string(rune('0'+i)))
		if err := os.MkdirAll(iface, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(iface, "bInterfaceClass"), []byte(class+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestListUSBSysfsDevices(t *testing.T) {
	root := t.TempDir()
	usbSysfsRoot = root
	fakeSysfsDevice(t, root, "1-4", map[string]string{
		"idVendor": "0951", "idProduct": "1666", "serial": "0012ab34",
		"manufacturer": "Kingston", "product": "DataTraveler",
		"bDeviceClass": "00", "authorized": "1",
	}, "08")
	fakeSysfsDevice(t, root, "1-1", map[string]string{
		"idVendor": "1d6b", "idProduct": "0002", "bDeviceClass": "09", "authorized": "1",
	})
	// A bus directory without vendor/product must be skipped.
	if err := os.MkdirAll(filepath.Join(root, "usb1"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Interface directories must not be listed as devices.
	fakeSysfsDevice(t, root, "1-4:1.0", map[string]string{"idVendor": "0951", "idProduct": "1666"})

	devices := listUSBSysfsDevices(rmm.USBPolicy{})
	if len(devices) != 2 {
		t.Fatalf("got %d devices: %+v", len(devices), devices)
	}
	var stick *usbLinuxDevice
	for i := range devices {
		if devices[i].Location == "1-4" {
			stick = &devices[i]
		}
	}
	if stick == nil {
		t.Fatalf("stick missing: %+v", devices)
	}
	if stick.InstanceID != `USB\VID_0951&PID_1666\0012AB34` {
		t.Fatalf("instance id %q", stick.InstanceID)
	}
	if !stick.Storage || stick.Class != "diskdrive" || stick.Name != "DataTraveler" || !stick.Enabled {
		t.Fatalf("got %+v", stick.USBDevice)
	}
	// Default denied policy blocks the stick but never the hub.
	if stick.PolicyAllowed || !stick.PolicyBlocked {
		t.Fatalf("policy flags %+v", stick.USBDevice)
	}
	for _, device := range devices {
		if device.Class == "hub" && !device.PolicyAllowed {
			t.Fatal("hubs must stay allowed")
		}
	}
}

func TestUSBSysfsEnableDisable(t *testing.T) {
	root := t.TempDir()
	usbSysfsRoot = root
	usbPolicyFile = filepath.Join(t.TempDir(), "usb-policy.json")
	fakeSysfsDevice(t, root, "1-4", map[string]string{
		"idVendor": "0951", "idProduct": "1666", "serial": "0012ab34", "authorized": "1",
	}, "08")

	a := &Agent{}
	if resp := a.USBAction("disable", `USB\VID_0951&PID_1666\0012AB34`, "all"); !resp.Success {
		t.Fatalf("disable failed: %s", resp.ErrorMsg)
	}
	if got := readUSBSysfsAttr(filepath.Join(root, "1-4"), usbAuthorized); got != "0" {
		t.Fatalf("authorized %q", got)
	}
	if resp := a.USBAction("enable", "1-4", "all"); !resp.Success {
		t.Fatalf("enable by port failed: %s", resp.ErrorMsg)
	}
	if got := readUSBSysfsAttr(filepath.Join(root, "1-4"), usbAuthorized); got != "1" {
		t.Fatalf("authorized %q", got)
	}
	if resp := a.USBAction("disable", `USB\VID_DEAD&PID_BEEF\X`, "all"); resp.Success {
		t.Fatal("unknown device must fail")
	}
	if resp := a.USBAction("set_write_protect", "true", "storage"); resp.Success {
		t.Fatal("write protection is Windows only")
	}
}

func TestUSBPolicyFileRoundTrip(t *testing.T) {
	root := t.TempDir()
	usbSysfsRoot = root
	usbPolicyFile = filepath.Join(t.TempDir(), "usb-policy.json")

	if policy := readUSBPolicy(); !policy.DefaultAllowed {
		t.Fatal("a missing policy file must allow USB")
	}
	fakeSysfsDevice(t, root, "1-4", map[string]string{
		"idVendor": "0951", "idProduct": "1666", "serial": "0012ab34", "authorized": "1",
	}, "08")

	a := &Agent{}
	if resp := a.USBAction("disable_all", "", "storage"); !resp.Success {
		t.Fatalf("disable_all failed: %s", resp.ErrorMsg)
	}
	if got := readUSBSysfsAttr(filepath.Join(root, "1-4"), usbAuthorized); got != "0" {
		t.Fatalf("enforcement did not deauthorize: %q", got)
	}
	if resp := a.USBAction("allow_device", "vid_0951&pid_1666", "storage"); !resp.Success {
		t.Fatalf("allow_device failed: %s", resp.ErrorMsg)
	}
	policy := readUSBPolicy()
	if policy.DefaultAllowed || len(policy.AllowedDevices) != 1 || policy.AllowedDevices[0] != "VID_0951&PID_1666" {
		t.Fatalf("got %+v", policy)
	}
	if got := readUSBSysfsAttr(filepath.Join(root, "1-4"), usbAuthorized); got != "1" {
		t.Fatalf("model rule did not re-authorize: %q", got)
	}
	info, err := os.Stat(usbPolicyFile)
	if err != nil || info.Mode().Perm() != usbPolicyPerms {
		t.Fatalf("policy file mode %v (%v)", info.Mode().Perm(), err)
	}
}

func TestMonitorUSBBlocksNewDevice(t *testing.T) {
	root := t.TempDir()
	usbSysfsRoot = root
	usbPolicyFile = filepath.Join(t.TempDir(), "usb-policy.json")
	if err := os.WriteFile(usbPolicyFile, []byte(`{"default_allowed":false}`), usbPolicyPerms); err != nil {
		t.Fatal(err)
	}

	a := &Agent{Logger: logrus.New()}
	a.MonitorUSB() // seeds an empty snapshot
	if len(a.usbSnapshot) != 0 {
		t.Fatalf("snapshot %+v", a.usbSnapshot)
	}
	fakeSysfsDevice(t, root, "1-4", map[string]string{
		"idVendor": "0951", "idProduct": "1666", "serial": "0012ab34", "authorized": "1",
	}, "08")

	a.MonitorUSB()
	if got := readUSBSysfsAttr(filepath.Join(root, "1-4"), usbAuthorized); got != "0" {
		t.Fatalf("a forbidden device must be deauthorized, authorized=%q", got)
	}
	if len(a.usbSnapshot) != 1 {
		t.Fatalf("snapshot %+v", a.usbSnapshot)
	}
}
