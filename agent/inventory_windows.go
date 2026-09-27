//go:build windows

package agent

import (
	wapf "github.com/wh1te909/go-win64api"
	"golang.org/x/sys/windows/registry"
)

type BitLockerInventory struct {
	DeviceID         string `json:"device_id"`
	DriveLetter      string `json:"drive_letter"`
	ProtectionStatus uint32 `json:"protection_status"`
	ConversionStatus uint32 `json:"conversion_status"`
	RecoveryKeyCount int    `json:"recovery_key_count"`
}

type AntivirusInventory struct {
	DisplayName            string `json:"display_name"`
	ProductState           uint32 `json:"product_state"`
	PathToSignedProductExe string `json:"path_to_signed_product_exe"`
	Timestamp              string `json:"timestamp"`
}

type FirewallProfileInventory struct {
	Enabled               bool   `json:"enabled"`
	DefaultInboundAction  uint64 `json:"default_inbound_action"`
	DefaultOutboundAction uint64 `json:"default_outbound_action"`
}

func keyExists(path string) (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err == nil {
		k.Close()
		return true, nil
	}
	if err == registry.ErrNotExist {
		return false, nil
	}
	return false, err
}

func (a *Agent) SystemRebootReasons() []string {
	reasons := make([]string, 0)

	for name, path := range map[string]string{
		"windows_update": `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`,
		"cbs":            `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`,
	} {
		ok, err := keyExists(path)
		if err != nil {
			a.Logger.Debugln("SystemRebootReasons():", err)
			continue
		}
		if ok {
			reasons = append(reasons, name)
		}
	}

	if pendingFileRenameOperations() {
		reasons = append(reasons, "pending_file_rename")
	}
	if pendingComputerRename() {
		reasons = append(reasons, "computer_rename")
	}
	return reasons
}

func pendingFileRenameOperations() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringsValue("PendingFileRenameOperations")
	return err == nil && len(v) > 0
}

func pendingComputerRename() bool {
	active, ok1 := computerNameValue(`SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName`)
	pending, ok2 := computerNameValue(`SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`)
	return ok1 && ok2 && active != "" && pending != "" && active != pending
}

func computerNameValue(path string) (string, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue("ComputerName")
	return v, err == nil
}

func GetFirewallProfilesInventory() map[string]FirewallProfileInventory {
	ret := make(map[string]FirewallProfileInventory)
	for name, path := range map[string]string{
		"domain":  `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile`,
		"private": `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`,
		"public":  `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile`,
	} {
		if profile, ok := readFirewallProfile(path); ok {
			ret[name] = profile
		}
	}
	return ret
}

func GetBitLockerInventory() ([]BitLockerInventory, error) {
	info, err := wapf.GetBitLockerRecoveryInfo()
	if err != nil {
		return nil, err
	}
	ret := make([]BitLockerInventory, 0, len(info))
	for _, item := range info {
		if item == nil {
			continue
		}
		ret = append(ret, BitLockerInventory{
			DeviceID:         item.DeviceID,
			DriveLetter:      item.DriveLetter,
			ProtectionStatus: item.ProtectionStatus,
			ConversionStatus: item.ConversionStatus,
			RecoveryKeyCount: len(item.RecoveryKeys),
		})
	}
	return ret, nil
}

func GetAntivirusInventory() ([]AntivirusInventory, error) {
	var dst []AntivirusInventory
	err := wmiQueryNamespace("SELECT displayName, productState, pathToSignedProductExe, timestamp FROM AntiVirusProduct", &dst, `ROOT\SecurityCenter2`)
	if err != nil {
		return []AntivirusInventory{}, err
	}
	return dst, nil
}

func readFirewallProfile(path string) (FirewallProfileInventory, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return FirewallProfileInventory{}, false
	}
	defer k.Close()

	enabled, _, _ := k.GetIntegerValue("EnableFirewall")
	inbound, _, _ := k.GetIntegerValue("DefaultInboundAction")
	outbound, _, _ := k.GetIntegerValue("DefaultOutboundAction")
	return FirewallProfileInventory{
		Enabled:               enabled != 0,
		DefaultInboundAction:  inbound,
		DefaultOutboundAction: outbound,
	}, true
}
