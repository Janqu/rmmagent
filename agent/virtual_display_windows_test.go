//go:build windows

package agent

import (
	"syscall"
	"testing"
)

func TestQdtHardwareIDsContain(t *testing.T) {
	ids := append(syscall.StringToUTF16(`PCI\VEN_1234`), syscall.StringToUTF16(qdtVirtualDisplayHardwareID)...)
	if !qdtHardwareIDsContain(ids, qdtVirtualDisplayHardwareID) {
		t.Fatal("QDT hardware ID was not found in MULTI_SZ")
	}
	if qdtHardwareIDsContain(ids, `Root\Other`) {
		t.Fatal("unrelated hardware ID matched")
	}
}
