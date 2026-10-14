package agent

import (
	"encoding/json"
	"math"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/nats-io/nats.go"
)

type RemoteControlHealth struct {
	Mode               string   `json:"mode"`
	Available          bool     `json:"available"`
	Transport          string   `json:"transport"`
	InteractiveSession string   `json:"interactive_session,omitempty"`
	Fallback           string   `json:"fallback,omitempty"`
	Capabilities       []string `json:"capabilities,omitempty"`
}

type remoteInputEvent struct {
	Type, Event, Key, Code     string
	X, Y, DeltaX, DeltaY       float64
	Button, Buttons, DeltaMode int
	Repeat                     bool
}

type remoteMonitor struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Width   int    `json:"width"`
	Height  int    `json:"height"`
	Primary bool   `json:"primary"`
}

const (
	remoteMaxEncodedFrameSize  = 896 << 10
	remoteMaxHelperMessageSize = remoteMaxEncodedFrameSize + (64 << 10)
)

func (a *Agent) remoteControlHealth() RemoteControlHealth {
	rc := RemoteControlHealth{Mode: "go_agent", Available: a.NatsServer != "" && remoteDesktopAvailable(), Transport: "nats", Capabilities: []string{"health", "command", "script", "terminal", "files", "session_lifecycle", "desktop_frames", "desktop_input", "desktop_shortcuts", "clipboard_text"}}
	if runtime.GOOS == "linux" {
		rc.InteractiveSession = linuxDisplaySession()
	}
	return rc
}

func (a *Agent) remoteControlCheckin() map[string]interface{} {
	rc := a.remoteControlHealth()
	out := map[string]interface{}{"mode": rc.Mode, "available": rc.Available, "transport": rc.Transport, "fallback": rc.Fallback, "capabilities": rc.Capabilities}
	if rc.InteractiveSession != "" {
		out["interactive_session"] = rc.InteractiveSession
	}
	return out
}

func remoteInt(payload map[string]string, key string, min, max int) (int, bool) {
	v, err := strconv.Atoi(payload[key])
	if err != nil || v < min || v > max {
		return 0, false
	}
	return v, true
}

func remoteCaptureSize(payload map[string]string, maxWidth, maxHeight int) (int, int, bool) {
	width, widthOK := remoteInt(payload, "width", 1, 7680)
	height, heightOK := remoteInt(payload, "height", 1, 4320)
	if !widthOK || !heightOK || maxWidth < 1 || maxHeight < 1 {
		return 0, 0, false
	}

	dpr := 1.0
	if raw := payload["dpr"]; raw != "" {
		parsed, err := strconv.ParseFloat(raw, 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || parsed < 0.5 || parsed > 4 {
			return 0, 0, false
		}
		dpr = parsed
	}

	width = min(maxWidth, max(1, int(math.Round(float64(width)*dpr))))
	height = min(maxHeight, max(1, int(math.Round(float64(height)*dpr))))
	return width, height, true
}

func parseRemoteEvent(raw string) (remoteInputEvent, bool) {
	var in struct {
		Type, Event, Key, Code     string
		X, Y, DeltaX, DeltaY       *float64
		Button, Buttons, DeltaMode *int
		Repeat                     bool
	}
	if len(raw) == 0 || len(raw) > 32<<10 || json.Unmarshal([]byte(raw), &in) != nil {
		return remoteInputEvent{}, false
	}
	e := remoteInputEvent{Type: in.Type, Event: in.Event, Key: in.Key, Code: in.Code, Repeat: in.Repeat}
	switch in.Type {
	case "pointer":
		if in.X == nil || in.Y == nil || in.Button == nil || in.Buttons == nil || *in.X < 0 || *in.X > 1 || *in.Y < 0 || *in.Y > 1 || *in.Button < -1 || *in.Button > 4 || *in.Buttons < 0 || *in.Buttons > 31 {
			return e, false
		}
		if in.Event != "pointermove" && in.Event != "pointerdown" && in.Event != "pointerup" {
			return e, false
		}
		if in.Event != "pointermove" && (*in.Button < 0 || *in.Button > 2) {
			return e, false
		}
		e.X, e.Y, e.Button, e.Buttons = *in.X, *in.Y, *in.Button, *in.Buttons
	case "wheel":
		if in.DeltaX == nil || in.DeltaY == nil || in.DeltaMode == nil || *in.DeltaMode < 0 || *in.DeltaMode > 2 || *in.DeltaX < -10000 || *in.DeltaX > 10000 || *in.DeltaY < -10000 || *in.DeltaY > 10000 {
			return e, false
		}
		e.DeltaX, e.DeltaY, e.DeltaMode = *in.DeltaX, *in.DeltaY, *in.DeltaMode
	case "key":
		if (in.Event != "keydown" && in.Event != "keyup") || len(in.Code) == 0 || len(in.Code) > 32 || len(in.Key) > 32 {
			return e, false
		}
	default:
		return e, false
	}
	return e, true
}

func decodeRemoteHelperMessage(raw []byte) (map[string]interface{}, bool) {
	var message struct {
		Action          string          `json:"action"`
		Mime            string          `json:"mime"`
		Data            string          `json:"data"`
		Seq             uint64          `json:"seq"`
		Monitors        []remoteMonitor `json:"monitors"`
		SelectedMonitor int             `json:"selected_monitor"`
		Text            string          `json:"text"`
		State           string          `json:"state"`
		Message         string          `json:"message"`
		Code            string          `json:"code"`
	}
	if json.Unmarshal(raw, &message) != nil {
		return nil, false
	}
	if message.Action == "ready" {
		return map[string]interface{}{"action": "ready", "monitors": message.Monitors, "selected_monitor": message.SelectedMonitor}, true
	}
	if message.Action == "clipboard" && validRemoteClipboardText(message.Text) {
		return map[string]interface{}{"action": "clipboard", "text": message.Text}, true
	}
	if message.Action == "status" && message.State == "clipboard" && message.Message == "updated" {
		return map[string]interface{}{"action": "status", "state": message.State, "message": message.Message}, true
	}
	if message.Action == "error" && (message.Code == "clipboard_unavailable" || message.Code == "invalid_clipboard" || message.Code == "unsupported_shortcut" || message.Code == "unsupported_secure_attention") && message.Message != "" && len(message.Message) <= 256 {
		return map[string]interface{}{"action": "error", "code": message.Code, "message": message.Message}, true
	}
	if message.Action != "frame" || message.Mime != "image/jpeg" || message.Data == "" || message.Seq == 0 {
		return nil, false
	}
	return map[string]interface{}{"action": "frame", "mime": message.Mime, "data": message.Data, "seq": message.Seq}, true
}

func validRemoteClipboardText(text string) bool {
	if len(text) > 64<<10 || !utf8.ValidString(text) || strings.IndexByte(text, 0) >= 0 {
		return false
	}
	for _, r := range text {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}

func validRemoteShortcut(name string) bool {
	switch name {
	case "ctrl_shift_escape", "alt_tab", "alt_f4", "win_d", "win_r", "win_e", "win_l",
		"ctrl_alt_end", "ctrl_alt_delete", "ctrl_c", "ctrl_v", "ctrl_x", "ctrl_a",
		"ctrl_z", "ctrl_y", "ctrl_s":
		return true
	}
	return false
}

func remoteFrameLimits(monitorID int) (int, int) {
	if monitorID == -1 {
		return 3840, 2160
	}
	return 2560, 1440
}

func wheelDelta(delta float64, mode int) int32 {
	scale := 120.0 / 100.0
	if mode == 1 {
		scale = 120.0 / 3.0
	} else if mode == 2 {
		scale = 120.0
	}
	value := int32(-delta * scale)
	if value > 1200 {
		return 1200
	}
	if value < -1200 {
		return -1200
	}
	if value == 0 && delta != 0 {
		if delta < 0 {
			return 1
		}
		return -1
	}
	return value
}

func (a *Agent) remoteControlStart(payload map[string]string, nc *nats.Conn) map[string]interface{} {
	return startRemoteDesktop(a, payload, nc)
}
func (a *Agent) remoteControlInput(payload map[string]string)    { inputRemoteDesktop(payload) }
func (a *Agent) remoteControlResize(payload map[string]string)   { resizeRemoteDesktop(payload) }
func (a *Agent) remoteControlDisplay(payload map[string]string)  { displayRemoteDesktop(payload) }
func (a *Agent) remoteControlShortcut(payload map[string]string) { shortcutRemoteDesktop(payload) }
func (a *Agent) remoteControlClipboardGet(payload map[string]string) {
	clipboardGetRemoteDesktop(payload)
}
func (a *Agent) remoteControlClipboardSet(payload map[string]string) {
	clipboardSetRemoteDesktop(payload)
}
func (a *Agent) remoteControlStop(payload map[string]string) map[string]interface{} {
	stopRemoteDesktop(payload["session_id"])
	return map[string]interface{}{"status": "stopped", "session_id": payload["session_id"]}
}
