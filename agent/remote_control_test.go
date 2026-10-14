package agent

import (
	"encoding/base64"
	"testing"
)

func TestRemoteControlHealthDefaults(t *testing.T) {
	a := &Agent{NatsServer: "wss://rmm.example.test/ws"}
	rc := a.remoteControlHealth()
	if rc.Mode != "go_agent" || rc.Transport != "nats" || rc.Fallback != "" {
		t.Fatalf("unexpected remote control defaults: %#v", rc)
	}
	if len(rc.Capabilities) == 0 {
		t.Fatalf("capabilities missing: %#v", rc)
	}
}

func TestRemoteControlCheckinShape(t *testing.T) {
	a := &Agent{}
	out := a.remoteControlCheckin()
	if out["mode"] != "go_agent" || out["transport"] != "nats" || out["fallback"] != "" {
		t.Fatalf("unexpected check-in payload: %#v", out)
	}
	if available, ok := out["available"].(bool); !ok || available {
		t.Fatalf("available should be false without NATS: %#v", out)
	}
	if caps, ok := out["capabilities"].([]string); !ok || len(caps) == 0 {
		t.Fatalf("capabilities missing: %#v", out)
	}
}

func TestRemoteControlSessionLifecycle(t *testing.T) {
	a := &Agent{}
	start := a.remoteControlStart(map[string]string{"mode": "control"}, nil)
	if start["status"] != "error" && start["status"] != "unsupported" {
		t.Fatalf("unexpected start response: %#v", start)
	}
	stop := a.remoteControlStop(map[string]string{"session_id": "session-1"})
	if stop["status"] != "stopped" || stop["session_id"] != "session-1" {
		t.Fatalf("unexpected stop response: %#v", stop)
	}
}

func TestRemoteControlInputValidation(t *testing.T) {
	if _, ok := parseRemoteEvent(`{"type":"pointer","event":"pointerdown","x":0.5,"y":0.5,"button":0,"buttons":1}`); !ok {
		t.Fatal("valid pointer input rejected")
	}
	if _, ok := parseRemoteEvent(`{"type":"pointer","event":"pointerdown","x":0.5,"y":0.5,"button":4,"buttons":1}`); ok {
		t.Fatal("unsupported mouse button accepted")
	}
	if _, ok := parseRemoteEvent(`{"type":"key","event":"keydown","code":"KeyA","key":"a"}`); !ok {
		t.Fatal("valid key input rejected")
	}
}

func TestRemoteControlWheelAndHelperFrame(t *testing.T) {
	if _, ok := parseRemoteEvent(`{"type":"wheel","deltaX":0,"deltaY":100,"deltaMode":0}`); !ok {
		t.Fatal("valid wheel rejected")
	}
	if _, ok := parseRemoteEvent(`{"type":"wheel","deltaX":0,"deltaY":1,"deltaMode":3}`); ok {
		t.Fatal("invalid deltaMode accepted")
	}
	message, ok := decodeRemoteHelperMessage([]byte(`{"action":"frame","mime":"image/jpeg","data":"YWJj","seq":7}`))
	if !ok {
		t.Fatal("valid helper frame rejected")
	}
	if seq, ok := message["seq"].(uint64); !ok || seq != 7 {
		t.Fatalf("frame seq lost integer type: %#v", message["seq"])
	}
	if got := wheelDelta(100, 0); got != -120 {
		t.Fatalf("pixel wheel conversion = %d", got)
	}
	if got := wheelDelta(-10000, 2); got != 1200 {
		t.Fatalf("wheel clamp = %d", got)
	}
}

func TestRemoteCaptureSizeUsesDevicePixelRatioWithinBounds(t *testing.T) {
	tests := []struct {
		name       string
		payload    map[string]string
		wantWidth  int
		wantHeight int
		wantOK     bool
	}{
		{name: "defaults DPR to one", payload: map[string]string{"width": "800", "height": "600"}, wantWidth: 800, wantHeight: 600, wantOK: true},
		{name: "scales fractional DPR", payload: map[string]string{"width": "800", "height": "600", "dpr": "1.5"}, wantWidth: 1200, wantHeight: 900, wantOK: true},
		{name: "caps high DPI viewport", payload: map[string]string{"width": "1600", "height": "900", "dpr": "2"}, wantWidth: 2560, wantHeight: 1440, wantOK: true},
		{name: "rejects excessive DPR", payload: map[string]string{"width": "800", "height": "600", "dpr": "5"}, wantOK: false},
		{name: "rejects non-finite DPR", payload: map[string]string{"width": "800", "height": "600", "dpr": "NaN"}, wantOK: false},
		{name: "rejects invalid dimensions", payload: map[string]string{"width": "0", "height": "600", "dpr": "1"}, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			width, height, ok := remoteCaptureSize(tt.payload, 2560, 1440)
			if ok != tt.wantOK || width != tt.wantWidth || height != tt.wantHeight {
				t.Fatalf("remoteCaptureSize() = (%d, %d, %v), want (%d, %d, %v)", width, height, ok, tt.wantWidth, tt.wantHeight, tt.wantOK)
			}
		})
	}
}

func TestRemoteFramePayloadLimitLeavesNATSHeadroom(t *testing.T) {
	if remoteMaxEncodedFrameSize != 896<<10 || remoteMaxEncodedFrameSize >= 1<<20 {
		t.Fatalf("unsafe encoded frame limit: %d", remoteMaxEncodedFrameSize)
	}
	if remoteMaxHelperMessageSize <= remoteMaxEncodedFrameSize {
		t.Fatalf("helper scanner has no JSON envelope headroom: %d", remoteMaxHelperMessageSize)
	}
	maxRaw := remoteMaxEncodedFrameSize / 4 * 3
	if base64.StdEncoding.EncodedLen(maxRaw) > remoteMaxEncodedFrameSize {
		t.Fatalf("raw boundary does not fit: %d", maxRaw)
	}
	if base64.StdEncoding.EncodedLen(maxRaw+1) <= remoteMaxEncodedFrameSize {
		t.Fatalf("raw boundary permits oversized frame: %d", maxRaw+1)
	}
}

func TestRemoteFrameLimits(t *testing.T) {
	if width, height := remoteFrameLimits(-1); width != 3840 || height != 2160 {
		t.Fatalf("multi-display limits = %dx%d", width, height)
	}
	if width, height := remoteFrameLimits(0); width != 2560 || height != 1440 {
		t.Fatalf("single-display limits = %dx%d", width, height)
	}
}

func TestRemoteControlReadyPreservesMonitorMetadata(t *testing.T) {
	message, ok := decodeRemoteHelperMessage([]byte(`{"action":"ready","monitors":[{"id":-1,"name":"All displays","width":3840,"height":1080,"primary":false},{"id":0,"name":"Display 1","width":1920,"height":1080,"primary":true}],"selected_monitor":-1}`))
	if !ok {
		t.Fatal("valid ready metadata rejected")
	}
	monitors, ok := message["monitors"].([]remoteMonitor)
	if !ok || len(monitors) != 2 || monitors[1].ID != 0 || !monitors[1].Primary {
		t.Fatalf("monitor metadata lost: %#v", message["monitors"])
	}
	if selected, ok := message["selected_monitor"].(int); !ok || selected != -1 {
		t.Fatalf("selected monitor lost: %#v", message["selected_monitor"])
	}
}

func TestRemoteControlClipboardAndShortcutValidation(t *testing.T) {
	for _, text := range []string{"", "hello", "line one\nline two\t✓"} {
		if !validRemoteClipboardText(text) {
			t.Fatalf("valid clipboard rejected: %q", text)
		}
	}
	for _, text := range []string{"nul\x00byte", "escape\x1b", string(make([]byte, (64<<10)+1))} {
		if validRemoteClipboardText(text) {
			t.Fatalf("invalid clipboard accepted: %d bytes", len(text))
		}
	}
	if !validRemoteShortcut("ctrl_shift_escape") || !validRemoteShortcut("ctrl_alt_delete") ||
		!validRemoteShortcut("ctrl_v") || !validRemoteShortcut("win_l") || validRemoteShortcut("powershell") {
		t.Fatal("shortcut allowlist mismatch")
	}
	message, ok := decodeRemoteHelperMessage([]byte(`{"action":"clipboard","text":"hello\nworld"}`))
	if !ok || message["text"] != "hello\nworld" {
		t.Fatalf("clipboard response lost: %#v", message)
	}
	errorMessage, ok := decodeRemoteHelperMessage([]byte(`{"action":"error","code":"unsupported_secure_attention","message":"secure desktop"}`))
	if !ok || errorMessage["code"] != "unsupported_secure_attention" {
		t.Fatalf("shortcut error lost: %#v", errorMessage)
	}
}
