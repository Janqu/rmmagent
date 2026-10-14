package agent

import (
	"bytes"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var backupDPAPIPrefix = []byte("QDT-BACKUP-DPAPI-1\x00")

func backupProtectLocalKey(key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length")
	}
	input := windows.DataBlob{Size: uint32(len(key)), Data: &key[0]}
	var output windows.DataBlob
	// User scope binds the key to the agent service identity (normally SYSTEM).
	if err := windows.CryptProtectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, fmt.Errorf("protect backup key: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	return append(bytes.Clone(backupDPAPIPrefix), unsafe.Slice(output.Data, int(output.Size))...), nil
}

func backupUnprotectLocalKey(stored []byte) ([]byte, error) {
	if len(stored) == 32 {
		return bytes.Clone(stored), nil
	} // Migrated atomically after validation.
	if !bytes.HasPrefix(stored, backupDPAPIPrefix) || len(stored) <= len(backupDPAPIPrefix) {
		return nil, fmt.Errorf("invalid protected backup key")
	}
	data := stored[len(backupDPAPIPrefix):]
	input := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var output windows.DataBlob
	if err := windows.CryptUnprotectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, fmt.Errorf("unlock backup key for agent service: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	return bytes.Clone(unsafe.Slice(output.Data, int(output.Size))), nil
}

func backupRestrictKeyPath(path string, dir bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	inherit := ""
	if dir {
		inherit = "OICI"
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;" + inherit + ";FA;;;SY)(A;" + inherit + ";FA;;;BA)(A;" + inherit + ";FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
