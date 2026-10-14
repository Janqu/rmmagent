//go:build windows

package agent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	qdtVirtualDisplayHardwareID = `Root\QDTVirtualDisplay`
	setupDiGetClassAll          = 0
	spdrpHardwareID             = 1
	difPropertyChange           = 0x12
	difRegisterDevice           = 0x19
	dicsEnable                  = 1
	dicsDisable                 = 2
	dicsFlagGlobal              = 1
)

var (
	setupapi                          = windows.NewLazySystemDLL("setupapi.dll")
	procSetupDiCreateDeviceInfoList   = setupapi.NewProc("SetupDiCreateDeviceInfoList")
	procSetupDiCreateDeviceInfoW      = setupapi.NewProc("SetupDiCreateDeviceInfoW")
	procSetupDiSetDeviceRegistryPropW = setupapi.NewProc("SetupDiSetDeviceRegistryPropertyW")
	procSetupDiCallClassInstaller     = setupapi.NewProc("SetupDiCallClassInstaller")
	procSetupDiDestroyDeviceInfoList  = setupapi.NewProc("SetupDiDestroyDeviceInfoList")
	procSetupDiGetClassDevsW          = setupapi.NewProc("SetupDiGetClassDevsW")
	procSetupDiEnumDeviceInfo         = setupapi.NewProc("SetupDiEnumDeviceInfo")
	procSetupDiGetDeviceRegistryPropW = setupapi.NewProc("SetupDiGetDeviceRegistryPropertyW")
	procSetupDiSetClassInstallParamsW = setupapi.NewProc("SetupDiSetClassInstallParamsW")
)

var qdtDisplayClassGUID = windows.GUID{Data1: 0x4d36e968, Data2: 0xe325, Data3: 0x11ce, Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}

type qdtDeviceInfoData struct {
	Size      uint32
	ClassGUID windows.GUID
	DevInst   uint32
	Reserved  uintptr
}

type qdtClassInstallHeader struct {
	Size            uint32
	InstallFunction uint32
}

type qdtPropChangeParams struct {
	Header      qdtClassInstallHeader
	StateChange uint32
	Scope       uint32
	HwProfile   uint32
}

func ensureQdtVirtualDisplay() (bool, error) {
	if len(enumerateRemoteMonitors()) != 0 {
		return false, nil
	}
	infoSet, info, found, err := findQdtVirtualDisplay()
	if err != nil {
		return false, err
	}
	if found {
		defer destroyQdtDeviceInfoList(infoSet)
		if err = setQdtVirtualDisplayState(infoSet, &info, true); err != nil {
			return false, fmt.Errorf("enable QDT virtual display: %w", err)
		}
		return true, nil
	}

	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	inf := filepath.Join(filepath.Dir(exe), "drivers", "qdt-virtual-display", "QdtVirtualDisplay.inf")
	if _, err = os.Stat(inf); err != nil {
		return false, errors.New("QDT virtual display package is not installed")
	}
	cmd := exec.Command("pnputil.exe", "/add-driver", inf, "/install")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, runErr := cmd.CombinedOutput(); runErr != nil {
		return false, fmt.Errorf("install QDT virtual display package: %w: %s", runErr, strings.TrimSpace(string(out)))
	}
	if err = createQdtVirtualDisplay(); err != nil {
		return false, err
	}
	return true, nil
}

func disableQdtVirtualDisplay() {
	infoSet, info, found, err := findQdtVirtualDisplay()
	if err != nil || !found {
		return
	}
	defer destroyQdtDeviceInfoList(infoSet)
	_ = setQdtVirtualDisplayState(infoSet, &info, false)
}

func createQdtVirtualDisplay() error {
	h, _, callErr := procSetupDiCreateDeviceInfoList.Call(uintptr(unsafe.Pointer(&qdtDisplayClassGUID)), 0)
	if h == 0 || h == ^uintptr(0) {
		return fmt.Errorf("SetupDiCreateDeviceInfoList: %w", callErr)
	}
	defer destroyQdtDeviceInfoList(windows.Handle(h))
	name, _ := windows.UTF16PtrFromString("QDT Virtual Display")
	info := qdtDeviceInfoData{Size: uint32(unsafe.Sizeof(qdtDeviceInfoData{}))}
	r, _, callErr := procSetupDiCreateDeviceInfoW.Call(h, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&qdtDisplayClassGUID)), 0, 0, 1, uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		return fmt.Errorf("SetupDiCreateDeviceInfo: %w", callErr)
	}
	hardwareID := syscall.StringToUTF16(qdtVirtualDisplayHardwareID + "\x00")
	r, _, callErr = procSetupDiSetDeviceRegistryPropW.Call(h, uintptr(unsafe.Pointer(&info)), spdrpHardwareID, uintptr(unsafe.Pointer(&hardwareID[0])), uintptr(len(hardwareID)*2))
	if r == 0 {
		return fmt.Errorf("set virtual display hardware id: %w", callErr)
	}
	r, _, callErr = procSetupDiCallClassInstaller.Call(difRegisterDevice, h, uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		return fmt.Errorf("register QDT virtual display: %w", callErr)
	}
	return nil
}

func findQdtVirtualDisplay() (windows.Handle, qdtDeviceInfoData, bool, error) {
	h, _, callErr := procSetupDiGetClassDevsW.Call(uintptr(unsafe.Pointer(&qdtDisplayClassGUID)), 0, 0, setupDiGetClassAll)
	if h == 0 || h == ^uintptr(0) {
		return 0, qdtDeviceInfoData{}, false, fmt.Errorf("SetupDiGetClassDevs: %w", callErr)
	}
	infoSet := windows.Handle(h)
	for index := uint32(0); ; index++ {
		info := qdtDeviceInfoData{Size: uint32(unsafe.Sizeof(qdtDeviceInfoData{}))}
		r, _, err := procSetupDiEnumDeviceInfo.Call(h, uintptr(index), uintptr(unsafe.Pointer(&info)))
		if r == 0 {
			if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
				return infoSet, qdtDeviceInfoData{}, false, nil
			}
			destroyQdtDeviceInfoList(infoSet)
			return 0, qdtDeviceInfoData{}, false, err
		}
		buf := make([]uint16, 256)
		var dataType, required uint32
		r, _, _ = procSetupDiGetDeviceRegistryPropW.Call(h, uintptr(unsafe.Pointer(&info)), spdrpHardwareID, uintptr(unsafe.Pointer(&dataType)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2), uintptr(unsafe.Pointer(&required)))
		if r != 0 && qdtHardwareIDsContain(buf, qdtVirtualDisplayHardwareID) {
			return infoSet, info, true, nil
		}
	}
}

func qdtHardwareIDsContain(ids []uint16, want string) bool {
	for len(ids) > 0 && ids[0] != 0 {
		n := 0
		for n < len(ids) && ids[n] != 0 {
			n++
		}
		if strings.EqualFold(syscall.UTF16ToString(ids[:n]), want) {
			return true
		}
		if n == len(ids) {
			break
		}
		ids = ids[n+1:]
	}
	return false
}

func setQdtVirtualDisplayState(infoSet windows.Handle, info *qdtDeviceInfoData, enable bool) error {
	state := uint32(dicsDisable)
	if enable {
		state = dicsEnable
	}
	params := qdtPropChangeParams{Header: qdtClassInstallHeader{Size: uint32(unsafe.Sizeof(qdtClassInstallHeader{})), InstallFunction: difPropertyChange}, StateChange: state, Scope: dicsFlagGlobal}
	r, _, callErr := procSetupDiSetClassInstallParamsW.Call(uintptr(infoSet), uintptr(unsafe.Pointer(info)), uintptr(unsafe.Pointer(&params)), unsafe.Sizeof(params))
	if r == 0 {
		return callErr
	}
	r, _, callErr = procSetupDiCallClassInstaller.Call(difPropertyChange, uintptr(infoSet), uintptr(unsafe.Pointer(info)))
	if r == 0 {
		return callErr
	}
	return nil
}

func destroyQdtDeviceInfoList(infoSet windows.Handle) {
	if infoSet != 0 {
		procSetupDiDestroyDeviceInfoList.Call(uintptr(infoSet))
	}
}
