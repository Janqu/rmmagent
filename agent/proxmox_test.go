//go:build !windows

package agent

import (
	"context"
	"github.com/ugorji/go/codec"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestProxmoxInventory(t *testing.T) {
	root := t.TempDir()
	node := filepath.Join(root, "nodes", "pve1")
	if err := os.MkdirAll(node, 0700); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(root, "local")
	if err := os.Symlink(node, local); err != nil {
		t.Fatal(err)
	}
	if proxmoxNode(local) != "pve1" || proxmoxNode(root) != "" || proxmoxNode(filepath.Join(root, "missing")) != "" {
		t.Fatal("host detection did not require a local Proxmox node directory")
	}
	version, api := filepath.Join(root, "pveversion"), filepath.Join(root, "pvesh")
	write := func(path, script string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write(version, "echo 'pve-manager/9.0.3/abcdef (running kernel: 6.14.8-2-pve)'")
	write(api, `[ "$1" = get ] && [ "$3" = --output-format ] && [ "$4" = json ]
case "$2" in
/nodes/pve1/qemu) echo '[{"vmid":200,"name":"db","status":"running","cpu":0.25,"cpus":4,"mem":1024,"maxmem":4096,"maxdisk":8192}]';;
/nodes/pve1/lxc) echo '[{"vmid":100,"name":"dns","status":"stopped","cpus":2,"template":1}]';;
*) exit 1;;
esac`)
	info := readProxmoxInventory(context.Background(), "pve1", version, api)
	if info.Version != "9.0.3" || len(info.Errors) != 0 || len(info.Guests) != 2 || info.Guests[0].Type != "lxc" || info.Guests[1].CPU != 0.25 || info.Guests[1].Name != "db" || info.CollectedAt == "" {
		t.Fatalf("inventory: %+v", info)
	}
	// The server rejects MessagePack time extensions; telemetry must stay JSON-compatible.
	var encoded []byte
	if err := codec.NewEncoderBytes(&encoded, new(codec.MsgpackHandle)).Encode(map[string]interface{}{"proxmox": info}); err != nil {
		t.Fatal(err)
	}
	handle := &codec.MsgpackHandle{}
	handle.MapType = reflect.TypeOf(map[string]interface{}{})
	handle.RawToString = true
	var decoded map[string]interface{}
	if err := codec.NewDecoderBytes(encoded, handle).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["proxmox"].(map[string]interface{})["collected_at"].(string); !ok {
		t.Fatal("timestamp is not JSON-compatible", decoded)
	}
	for _, output := range []string{"null", "{}", "bad-json", `[{"vmid":1}]`, `[{"vmid":100,"mem":-1}]`} {
		write(api, "echo '"+output+"'")
		info = readProxmoxInventory(context.Background(), "pve1", version, api)
		if len(info.Errors) == 0 || len(info.Guests) != 0 {
			t.Fatalf("accepted %s: %+v", output, info)
		}
	}
	write(api, `case "$2" in */qemu) echo '[]';; *) echo 'permission denied' >&2; exit 1;; esac`)
	info = readProxmoxInventory(context.Background(), "pve1", version, api)
	if info.Node != "pve1" || len(info.Errors) != 1 {
		t.Fatal("partial inventory lost host or error", info)
	}
	write(api, "exec sleep 30")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	info = readProxmoxInventory(ctx, "pve1", version, api)
	if len(info.Errors) != 2 {
		t.Fatal("timeout was not reported", info)
	}
}
