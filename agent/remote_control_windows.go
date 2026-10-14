//go:build windows

package agent

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/gonutz/w32/v2"
	"github.com/nats-io/nats.go"
	"github.com/ugorji/go/codec"
	"golang.org/x/sys/windows"
)

type remoteDesktopSession struct {
	id             string
	in             *os.File
	out            *os.File
	proc, job      windows.Handle
	nc             *nats.Conn
	virtualDisplay bool
	mu             sync.Mutex
	once           sync.Once
}

type remoteCaptureRect struct {
	x, y, width, height int
	primary             bool
}

type remoteHelperCommand struct {
	Type      string  `json:"type"`
	Event     string  `json:"event,omitempty"`
	Key       string  `json:"key,omitempty"`
	Code      string  `json:"code,omitempty"`
	X         float64 `json:"x,omitempty"`
	Y         float64 `json:"y,omitempty"`
	DeltaX    float64 `json:"deltaX,omitempty"`
	DeltaY    float64 `json:"deltaY,omitempty"`
	Button    int     `json:"button,omitempty"`
	Buttons   int     `json:"buttons,omitempty"`
	DeltaMode int     `json:"deltaMode,omitempty"`
	Repeat    bool    `json:"repeat,omitempty"`
	Width     int     `json:"width,omitempty"`
	Height    int     `json:"height,omitempty"`
	MonitorID int     `json:"monitor_id,omitempty"`
	Name      string  `json:"name,omitempty"`
	Text      string  `json:"text,omitempty"`
}

var remoteDesktop struct {
	sync.Mutex
	session *remoteDesktopSession
}

func remoteDesktopAvailable() bool { return len(activeSessions()) > 0 }

func remoteTopic(agentID, sessionID string) string { return agentID + ".remote." + sessionID }

func startRemoteDesktop(a *Agent, p map[string]string, nc *nats.Conn) map[string]interface{} {
	id := strings.TrimSpace(p["session_id"])
	if id == "" || len(id) > 128 || nc == nil {
		return map[string]interface{}{"status": "error", "message": "invalid remote session"}
	}
	width, height, sizeOK := remoteCaptureSize(p, 2560, 1440)
	if !sizeOK {
		return map[string]interface{}{"status": "error", "message": "invalid display size"}
	}
	remoteDesktop.Lock()
	defer remoteDesktop.Unlock()
	if remoteDesktop.session != nil {
		return map[string]interface{}{"status": "error", "message": "a remote session is already active"}
	}
	virtualDisplay, err := ensureQdtVirtualDisplay()
	if err != nil {
		return map[string]interface{}{"status": "error", "message": err.Error()}
	}
	if virtualDisplay {
		defer func() {
			if remoteDesktop.session == nil {
				disableQdtVirtualDisplay()
			}
		}()
		time.Sleep(2 * time.Second)
	}
	s, err := launchRemoteDesktopHelper(id, nc)
	if err != nil {
		return map[string]interface{}{"status": "error", "message": err.Error()}
	}
	s.virtualDisplay = virtualDisplay
	remoteDesktop.session = s
	monitorID := -1
	if raw := p["monitor_id"]; raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= -1 && parsed < 16 {
			monitorID = parsed
		}
	}
	_ = json.NewEncoder(s.in).Encode(remoteHelperCommand{Type: "resize", Width: width, Height: height, MonitorID: monitorID})
	go relayRemoteFrames(a.AgentID, s)
	return map[string]interface{}{"status": "started", "session_id": id}
}

func inputRemoteDesktop(p map[string]string) {
	e, ok := parseRemoteEvent(p["event"])
	if !ok {
		return
	}
	withRemoteSession(p["session_id"], func(s *remoteDesktopSession) { s.mu.Lock(); defer s.mu.Unlock(); _ = json.NewEncoder(s.in).Encode(e) })
}

func resizeRemoteDesktop(p map[string]string) {
	w, h, sizeOK := remoteCaptureSize(p, 2560, 1440)
	if !sizeOK {
		return
	}
	withRemoteSession(p["session_id"], func(s *remoteDesktopSession) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = json.NewEncoder(s.in).Encode(remoteHelperCommand{Type: "resize", Width: w, Height: h, MonitorID: -2})
	})
}

func displayRemoteDesktop(p map[string]string) {
	id, ok := remoteInt(p, "monitor_id", -1, 15)
	if !ok {
		return
	}
	withRemoteSession(p["session_id"], func(s *remoteDesktopSession) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = json.NewEncoder(s.in).Encode(remoteHelperCommand{Type: "display", MonitorID: id})
	})
}

func shortcutRemoteDesktop(p map[string]string) {
	if !validRemoteShortcut(p["name"]) {
		return
	}
	withRemoteSession(p["session_id"], func(s *remoteDesktopSession) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = json.NewEncoder(s.in).Encode(remoteHelperCommand{Type: "shortcut", Name: p["name"]})
	})
}

func clipboardGetRemoteDesktop(p map[string]string) {
	withRemoteSession(p["session_id"], func(s *remoteDesktopSession) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = json.NewEncoder(s.in).Encode(remoteHelperCommand{Type: "clipboard_get"})
	})
}

func clipboardSetRemoteDesktop(p map[string]string) {
	if !validRemoteClipboardText(p["text"]) {
		return
	}
	withRemoteSession(p["session_id"], func(s *remoteDesktopSession) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = json.NewEncoder(s.in).Encode(remoteHelperCommand{Type: "clipboard_set", Text: p["text"]})
	})
}

func withRemoteSession(id string, fn func(*remoteDesktopSession)) {
	remoteDesktop.Lock()
	s := remoteDesktop.session
	remoteDesktop.Unlock()
	if s != nil && s.id == id {
		fn(s)
	}
}

func stopRemoteDesktop(id string) {
	remoteDesktop.Lock()
	s := remoteDesktop.session
	if s == nil || s.id != id {
		remoteDesktop.Unlock()
		return
	}
	remoteDesktop.session = nil
	remoteDesktop.Unlock()
	s.once.Do(func() {
		_ = s.in.Close()
		_ = s.out.Close()
		if s.job != 0 {
			_ = windows.TerminateJobObject(s.job, 0)
			_ = windows.CloseHandle(s.job)
		}
		if s.proc != 0 {
			_ = windows.CloseHandle(s.proc)
		}
		if s.virtualDisplay {
			disableQdtVirtualDisplay()
		}
	})
}

func launchRemoteDesktopHelper(id string, nc *nats.Conn) (*remoteDesktopSession, error) {
	token, err := getUserToken()
	if err != nil {
		return nil, fmt.Errorf("no interactive user session: %w", err)
	}
	defer token.Close()
	inR, inW, err := createInheritablePipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := createInheritablePipe()
	if err != nil {
		windows.CloseHandle(inR)
		windows.CloseHandle(inW)
		return nil, err
	}
	cleanup := func() {
		windows.CloseHandle(inR)
		windows.CloseHandle(inW)
		windows.CloseHandle(outR)
		windows.CloseHandle(outW)
	}
	if err = windows.SetHandleInformation(inW, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		cleanup()
		return nil, err
	}
	if err = windows.SetHandleInformation(outR, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		cleanup()
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		cleanup()
		return nil, err
	}
	env, err := CreateEnvironmentBlock(syscall.Token(token.Token()))
	if err != nil {
		cleanup()
		return nil, err
	}
	defer DestroyEnvironmentBlock(env)
	desktop := windows.StringToUTF16Ptr(`winsta0\default`)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desktop, Flags: windows.STARTF_USESTDHANDLES, StdInput: inR, StdOutput: outW, StdErr: outW}
	cmd := windows.StringToUTF16Ptr(quoteIfNeeded(exe) + " --remote-desktop-helper")
	var pi windows.ProcessInformation
	err = CreateProcessAsUser(syscall.Token(token.Token()), nil, cmd, nil, nil, true, windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, env, nil, &si, &pi)
	if err != nil {
		cleanup()
		return nil, err
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(inR)
	windows.CloseHandle(outW)
	job, err := createTerminalJobObject()
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(inW)
		windows.CloseHandle(outR)
		return nil, err
	}
	if err = windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(job)
		windows.CloseHandle(inW)
		windows.CloseHandle(outR)
		return nil, err
	}
	return &remoteDesktopSession{id: id, in: os.NewFile(uintptr(inW), "remote-input"), out: os.NewFile(uintptr(outR), "remote-output"), proc: pi.Process, job: job, nc: nc}, nil
}

func relayRemoteFrames(agentID string, s *remoteDesktopSession) {
	scanner := bufio.NewScanner(s.out)
	scanner.Buffer(make([]byte, 64<<10), remoteMaxHelperMessageSize)
	topic := remoteTopic(agentID, s.id)
	for scanner.Scan() {
		value, ok := decodeRemoteHelperMessage(scanner.Bytes())
		if !ok {
			continue
		}
		var data []byte
		if codec.NewEncoderBytes(&data, new(codec.MsgpackHandle)).Encode(value) != nil || s.nc.Publish(topic, data) != nil {
			break
		}
	}
	var data []byte
	_ = codec.NewEncoderBytes(&data, new(codec.MsgpackHandle)).Encode(map[string]interface{}{"action": "end", "reason": "desktop helper stopped"})
	_ = s.nc.Publish(topic, data)
	stopRemoteDesktop(s.id)
}

func RunRemoteDesktopHelper(in io.Reader, out io.Writer) error {
	monitors := enumerateRemoteMonitors()
	if len(monitors) == 0 {
		return errors.New("no desktop monitors available")
	}
	enc := json.NewEncoder(out)
	var encMu sync.Mutex
	send := func(value map[string]interface{}) error { encMu.Lock(); defer encMu.Unlock(); return enc.Encode(value) }
	public := make([]remoteMonitor, 0, len(monitors)+1)
	virtual := virtualRemoteRect()
	public = append(public, remoteMonitor{ID: -1, Name: "All displays", Width: virtual.width, Height: virtual.height})
	for id, monitor := range monitors {
		public = append(public, remoteMonitor{ID: id, Name: fmt.Sprintf("Display %d", id+1), Width: monitor.width, Height: monitor.height, Primary: monitor.primary})
	}
	_ = send(map[string]interface{}{"action": "ready", "monitors": public, "selected_monitor": -1})
	state := struct {
		sync.RWMutex
		width, height, monitor int
	}{width: 1280, height: 720, monitor: -1}
	go func() {
		dec := json.NewDecoder(in)
		for {
			var command remoteHelperCommand
			if dec.Decode(&command) != nil {
				return
			}
			state.Lock()
			switch command.Type {
			case "resize":
				if command.Width >= 1 && command.Width <= 7680 && command.Height >= 1 && command.Height <= 4320 {
					state.width, state.height = command.Width, command.Height
				}
				if command.MonitorID >= -1 {
					state.monitor = command.MonitorID
				}
			case "display":
				if command.MonitorID >= -1 && command.MonitorID < len(monitors) {
					state.monitor = command.MonitorID
				}
			case "shortcut":
				state.Unlock()
				if command.Name == "ctrl_alt_delete" {
					_ = send(map[string]interface{}{"action": "error", "code": "unsupported_secure_attention", "message": "Ctrl+Alt+Delete requires the Windows secure desktop."})
				} else if !sendRemoteShortcut(command.Name) {
					_ = send(map[string]interface{}{"action": "error", "code": "unsupported_shortcut", "message": "Unsupported remote shortcut."})
				}
				continue
			case "clipboard_get":
				state.Unlock()
				text, err := readRemoteClipboard()
				if err != nil {
					_ = send(map[string]interface{}{"action": "error", "code": "clipboard_unavailable", "message": "Windows text clipboard is unavailable."})
				} else {
					_ = send(map[string]interface{}{"action": "clipboard", "text": text})
				}
				continue
			case "clipboard_set":
				state.Unlock()
				if !validRemoteClipboardText(command.Text) || writeRemoteClipboard(command.Text) != nil {
					_ = send(map[string]interface{}{"action": "error", "code": "invalid_clipboard", "message": "Clipboard text was rejected."})
				} else {
					_ = send(map[string]interface{}{"action": "status", "state": "clipboard", "message": "updated"})
				}
				continue
			default:
				display := virtual
				if state.monitor >= 0 && state.monitor < len(monitors) {
					display = monitors[state.monitor]
				}
				state.Unlock()
				applyRemoteInputForDisplay(remoteInputEvent{Type: command.Type, Event: command.Event, Key: command.Key, Code: command.Code, X: command.X, Y: command.Y, DeltaX: command.DeltaX, DeltaY: command.DeltaY, Button: command.Button, Buttons: command.Buttons, DeltaMode: command.DeltaMode, Repeat: command.Repeat}, display, virtual)
				continue
			}
			state.Unlock()
		}
	}()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var seq uint64
	for range ticker.C {
		state.RLock()
		width, height, monitorID := state.width, state.height, state.monitor
		state.RUnlock()
		display := virtual
		if monitorID >= 0 && monitorID < len(monitors) {
			display = monitors[monitorID]
		}
		maxWidth, maxHeight := remoteFrameLimits(monitorID)
		frame, err := captureRemoteJPEG(display, min(width, maxWidth), min(height, maxHeight))
		if err != nil {
			return err
		}
		if len(frame) == 0 || base64.StdEncoding.EncodedLen(len(frame)) > remoteMaxEncodedFrameSize {
			continue
		}
		seq++
		err = send(map[string]interface{}{"action": "frame", "mime": "image/jpeg", "data": base64.StdEncoding.EncodeToString(frame), "seq": seq})
		if err != nil {
			return err
		}
	}
	return nil
}

func virtualRemoteRect() remoteCaptureRect {
	return remoteCaptureRect{x: w32.GetSystemMetrics(w32.SM_XVIRTUALSCREEN), y: w32.GetSystemMetrics(w32.SM_YVIRTUALSCREEN), width: w32.GetSystemMetrics(w32.SM_CXVIRTUALSCREEN), height: w32.GetSystemMetrics(w32.SM_CYVIRTUALSCREEN)}
}

func enumerateRemoteMonitors() []remoteCaptureRect {
	var monitors []remoteCaptureRect
	callback := syscall.NewCallback(func(handle, _ uintptr, rectPtr, _ uintptr) uintptr {
		if len(monitors) >= 16 {
			return 1
		}
		var info w32.MONITORINFO
		if w32.GetMonitorInfo(w32.HMONITOR(handle), &info) {
			r := info.RcMonitor
			monitors = append(monitors, remoteCaptureRect{x: int(r.Left), y: int(r.Top), width: int(r.Right - r.Left), height: int(r.Bottom - r.Top), primary: info.DwFlags&w32.MONITORINFOF_PRIMARY != 0})
		} else if rectPtr != 0 {
			r := (*w32.RECT)(unsafe.Pointer(rectPtr))
			monitors = append(monitors, remoteCaptureRect{x: int(r.Left), y: int(r.Top), width: int(r.Right - r.Left), height: int(r.Bottom - r.Top)})
		}
		return 1
	})
	w32.EnumDisplayMonitors(0, nil, callback, 0)
	return monitors
}

func captureRemoteJPEG(display remoteCaptureRect, maxW, maxH int) ([]byte, error) {
	if display.width < 1 || display.height < 1 || maxW < 1 || maxH < 1 {
		return nil, errors.New("desktop is unavailable")
	}
	w, h := display.width, display.height
	if w > maxW {
		h = h * maxW / w
		w = maxW
	}
	if h > maxH {
		w = w * maxH / h
		h = maxH
	}
	screen := w32.GetDC(0)
	if screen == 0 {
		return nil, errors.New("GetDC failed")
	}
	defer w32.ReleaseDC(0, screen)
	mem := w32.CreateCompatibleDC(screen)
	if mem == 0 {
		return nil, errors.New("CreateCompatibleDC failed")
	}
	defer w32.DeleteDC(mem)
	info := w32.BITMAPINFO{BmiHeader: w32.BITMAPINFOHEADER{BiSize: uint32(unsafe.Sizeof(w32.BITMAPINFOHEADER{})), BiWidth: int32(w), BiHeight: -int32(h), BiPlanes: 1, BiBitCount: 32, BiCompression: w32.BI_RGB}}
	var bits unsafe.Pointer
	bitmap := w32.CreateDIBSection(mem, &info, w32.DIB_RGB_COLORS, &bits, 0, 0)
	if bitmap == 0 {
		return nil, errors.New("CreateDIBSection failed")
	}
	defer w32.DeleteObject(w32.HGDIOBJ(bitmap))
	old := w32.SelectObject(mem, w32.HGDIOBJ(bitmap))
	defer w32.SelectObject(mem, old)
	if !w32.StretchBlt(mem, 0, 0, w, h, screen, display.x, display.y, display.width, display.height, w32.SRCCOPY|w32.CAPTUREBLT) {
		return nil, errors.New("desktop capture failed")
	}
	raw := unsafe.Slice((*byte)(bits), w*h*4)
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < w*h; i++ {
		img.Pix[i*4], img.Pix[i*4+1], img.Pix[i*4+2], img.Pix[i*4+3] = raw[i*4+2], raw[i*4+1], raw[i*4], 255
	}
	for _, quality := range []int{72, 58, 44, 30} {
		var b strings.Builder
		if err := jpeg.Encode(&b, img, &jpeg.Options{Quality: quality}); err != nil {
			return nil, err
		}
		if base64.StdEncoding.EncodedLen(b.Len()) <= remoteMaxEncodedFrameSize {
			return []byte(b.String()), nil
		}
	}
	if w > 640 || h > 360 {
		return captureRemoteJPEG(display, max(640, w*3/4), max(360, h*3/4))
	}
	return nil, nil
}

func applyRemoteInput(e remoteInputEvent) {
	virtual := virtualRemoteRect()
	applyRemoteInputForDisplay(e, virtual, virtual)
}

func applyRemoteInputForDisplay(e remoteInputEvent, display, virtual remoteCaptureRect) {
	switch e.Type {
	case "pointer":
		flags := uint32(w32.MOUSEEVENTF_MOVE | w32.MOUSEEVENTF_ABSOLUTE | w32.MOUSEEVENTF_VIRTUALDESK)
		if e.Event == "pointerdown" {
			flags |= []uint32{w32.MOUSEEVENTF_LEFTDOWN, w32.MOUSEEVENTF_MIDDLEDOWN, w32.MOUSEEVENTF_RIGHTDOWN}[min(e.Button, 2)]
		}
		if e.Event == "pointerup" {
			flags |= []uint32{w32.MOUSEEVENTF_LEFTUP, w32.MOUSEEVENTF_MIDDLEUP, w32.MOUSEEVENTF_RIGHTUP}[min(e.Button, 2)]
		}
		x := display.x + int(e.X*float64(max(1, display.width-1)))
		y := display.y + int(e.Y*float64(max(1, display.height-1)))
		dx := int32(float64(x-virtual.x) * 65535 / float64(max(1, virtual.width-1)))
		dy := int32(float64(y-virtual.y) * 65535 / float64(max(1, virtual.height-1)))
		dx, dy = max(0, min(65535, dx)), max(0, min(65535, dy))
		w32.SendInput(w32.MouseInput(w32.MOUSEINPUT{Dx: dx, Dy: dy, Flags: flags}))
	case "wheel":
		w32.SendInput(w32.MouseInput(w32.MOUSEINPUT{MouseData: uint32(wheelDelta(e.DeltaY, e.DeltaMode)), Flags: w32.MOUSEEVENTF_WHEEL}))
	case "key":
		if vk, ok := remoteVK(e.Code); ok {
			flags := uint32(0)
			if e.Event == "keyup" {
				flags = w32.KEYEVENTF_KEYUP
			}
			w32.SendInput(w32.KeyboardInput(w32.KEYBDINPUT{Vk: vk, Flags: flags}))
		}
	}
}

func remoteVK(code string) (uint16, bool) {
	if len(code) == 4 && strings.HasPrefix(code, "Key") && code[3] >= 'A' && code[3] <= 'Z' {
		return uint16(code[3]), true
	}
	if len(code) == 6 && strings.HasPrefix(code, "Digit") && code[5] >= '0' && code[5] <= '9' {
		return uint16(code[5]), true
	}
	m := map[string]uint16{
		"Enter": w32.VK_RETURN, "Escape": w32.VK_ESCAPE, "Backspace": w32.VK_BACK, "Tab": w32.VK_TAB, "Space": w32.VK_SPACE,
		"ArrowLeft": w32.VK_LEFT, "ArrowRight": w32.VK_RIGHT, "ArrowUp": w32.VK_UP, "ArrowDown": w32.VK_DOWN,
		"Delete": w32.VK_DELETE, "Insert": w32.VK_INSERT, "Home": w32.VK_HOME, "End": w32.VK_END, "PageUp": w32.VK_PRIOR, "PageDown": w32.VK_NEXT,
		"ShiftLeft": w32.VK_SHIFT, "ShiftRight": w32.VK_SHIFT, "ControlLeft": w32.VK_CONTROL, "ControlRight": w32.VK_CONTROL, "AltLeft": w32.VK_MENU, "AltRight": w32.VK_MENU,
		"MetaLeft": w32.VK_LWIN, "MetaRight": w32.VK_RWIN, "ContextMenu": w32.VK_APPS, "CapsLock": w32.VK_CAPITAL, "Pause": w32.VK_PAUSE, "PrintScreen": w32.VK_SNAPSHOT,
		"NumpadMultiply": w32.VK_MULTIPLY, "NumpadAdd": w32.VK_ADD, "NumpadSubtract": w32.VK_SUBTRACT, "NumpadDecimal": w32.VK_DECIMAL, "NumpadDivide": w32.VK_DIVIDE,
		"Semicolon": w32.VK_OEM_1, "Equal": w32.VK_OEM_PLUS, "Comma": w32.VK_OEM_COMMA, "Minus": w32.VK_OEM_MINUS, "Period": w32.VK_OEM_PERIOD, "Slash": w32.VK_OEM_2,
		"Backquote": w32.VK_OEM_3, "BracketLeft": w32.VK_OEM_4, "Backslash": w32.VK_OEM_5, "BracketRight": w32.VK_OEM_6, "Quote": w32.VK_OEM_7,
	}
	v, ok := m[code]
	if ok {
		return v, true
	}
	if len(code) >= 2 && code[0] == 'F' {
		if number, err := strconv.Atoi(code[1:]); err == nil && number >= 1 && number <= 12 {
			return uint16(w32.VK_F1 + number - 1), true
		}
	}
	if len(code) == 7 && strings.HasPrefix(code, "Numpad") && code[6] >= '0' && code[6] <= '9' {
		return uint16(w32.VK_NUMPAD0 + code[6] - '0'), true
	}
	return v, ok
}

func sendRemoteShortcut(name string) bool {
	shortcuts := map[string][]uint16{
		"ctrl_shift_escape": {w32.VK_CONTROL, w32.VK_SHIFT, w32.VK_ESCAPE},
		"alt_tab":           {w32.VK_MENU, w32.VK_TAB},
		"alt_f4":            {w32.VK_MENU, w32.VK_F4},
		"win_d":             {w32.VK_LWIN, 'D'},
		"win_r":             {w32.VK_LWIN, 'R'},
		"win_e":             {w32.VK_LWIN, 'E'},
		"win_l":             {w32.VK_LWIN, 'L'},
		"ctrl_alt_end":      {w32.VK_CONTROL, w32.VK_MENU, w32.VK_END},
		"ctrl_c":            {w32.VK_CONTROL, 'C'},
		"ctrl_v":            {w32.VK_CONTROL, 'V'},
		"ctrl_x":            {w32.VK_CONTROL, 'X'},
		"ctrl_a":            {w32.VK_CONTROL, 'A'},
		"ctrl_z":            {w32.VK_CONTROL, 'Z'},
		"ctrl_y":            {w32.VK_CONTROL, 'Y'},
		"ctrl_s":            {w32.VK_CONTROL, 'S'},
	}
	keys, ok := shortcuts[name]
	if !ok {
		return false
	}
	inputs := make([]w32.INPUT, 0, len(keys)*2)
	for _, key := range keys {
		inputs = append(inputs, w32.KeyboardInput(w32.KEYBDINPUT{Vk: key}))
	}
	for i := len(keys) - 1; i >= 0; i-- {
		inputs = append(inputs, w32.KeyboardInput(w32.KEYBDINPUT{Vk: keys[i], Flags: w32.KEYEVENTF_KEYUP}))
	}
	return w32.SendInput(inputs...) == uint32(len(inputs))
}

var procGlobalSize = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalSize")

func openRemoteClipboard() bool {
	for attempt := 0; attempt < 5; attempt++ {
		if w32.OpenClipboard(0) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func readRemoteClipboard() (string, error) {
	if !openRemoteClipboard() {
		return "", errors.New("OpenClipboard failed")
	}
	defer w32.CloseClipboard()
	handle := w32.GetClipboardData(w32.CF_UNICODETEXT)
	if handle == 0 {
		return "", errors.New("CF_UNICODETEXT unavailable")
	}
	size, _, _ := procGlobalSize.Call(uintptr(handle))
	if size == 0 || size > (64<<10)+2 {
		return "", errors.New("clipboard text too large")
	}
	pointer := w32.GlobalLock(w32.HGLOBAL(handle))
	if pointer == nil {
		return "", errors.New("GlobalLock failed")
	}
	defer w32.GlobalUnlock(w32.HGLOBAL(handle))
	units := unsafe.Slice((*uint16)(pointer), size/2)
	end := 0
	for end < len(units) && units[end] != 0 {
		end++
	}
	text := windows.UTF16ToString(units[:end])
	if !validRemoteClipboardText(text) {
		return "", errors.New("invalid clipboard text")
	}
	return text, nil
}

func writeRemoteClipboard(text string) error {
	if !validRemoteClipboardText(text) {
		return errors.New("invalid clipboard text")
	}
	units, err := windows.UTF16FromString(text)
	if err != nil {
		return err
	}
	bytes := uint32(len(units) * 2)
	handle := w32.GlobalAlloc(w32.GMEM_MOVEABLE, bytes)
	if handle == 0 {
		return errors.New("GlobalAlloc failed")
	}
	pointer := w32.GlobalLock(handle)
	if pointer == nil {
		w32.GlobalFree(handle)
		return errors.New("GlobalLock failed")
	}
	copy(unsafe.Slice((*uint16)(pointer), len(units)), units)
	w32.GlobalUnlock(handle)
	if !openRemoteClipboard() {
		w32.GlobalFree(handle)
		return errors.New("OpenClipboard failed")
	}
	defer w32.CloseClipboard()
	if !w32.EmptyClipboard() || w32.SetClipboardData(w32.CF_UNICODETEXT, w32.HANDLE(handle)) == 0 {
		w32.GlobalFree(handle)
		return errors.New("SetClipboardData failed")
	}
	return nil // Windows owns handle after SetClipboardData succeeds.
}
