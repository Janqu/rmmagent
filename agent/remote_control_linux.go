//go:build linux

package agent

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/ugorji/go/codec"
)

const (
	linuxDesktopWidth  = 1920
	linuxDesktopHeight = 1080
)

type remoteDesktopSession struct {
	id   string
	in   io.WriteCloser
	out  io.ReadCloser
	cmd  *exec.Cmd
	nc   *nats.Conn
	mu   sync.Mutex
	once sync.Once
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

type linuxDesktopState struct {
	sync.RWMutex
	width, height int
}

var remoteDesktop struct {
	sync.Mutex
	session *remoteDesktopSession
}

func remoteDesktopAvailable() bool { return linuxDesktopDependencies() == nil }

func remoteTopic(agentID, sessionID string) string { return agentID + ".remote." + sessionID }

func startRemoteDesktop(a *Agent, p map[string]string, nc *nats.Conn) map[string]interface{} {
	id := strings.TrimSpace(p["session_id"])
	if id == "" || len(id) > 128 || nc == nil {
		return map[string]interface{}{"status": "error", "message": "invalid remote session"}
	}
	width, height, ok := remoteCaptureSize(p, linuxDesktopWidth, linuxDesktopHeight)
	if !ok {
		return map[string]interface{}{"status": "error", "message": "invalid display size"}
	}
	if err := linuxDesktopDependencies(); err != nil {
		return map[string]interface{}{"status": "error", "message": err.Error()}
	}
	remoteDesktop.Lock()
	defer remoteDesktop.Unlock()
	if remoteDesktop.session != nil {
		return map[string]interface{}{"status": "error", "message": "a remote session is already active"}
	}
	s, err := launchRemoteDesktopHelper(id, nc)
	if err != nil {
		return map[string]interface{}{"status": "error", "message": err.Error()}
	}
	remoteDesktop.session = s
	_ = json.NewEncoder(s.in).Encode(remoteHelperCommand{Type: "resize", Width: width, Height: height, MonitorID: 0})
	go relayRemoteFrames(a.AgentID, s)
	return map[string]interface{}{"status": "started", "session_id": id}
}

func inputRemoteDesktop(p map[string]string) {
	e, ok := parseRemoteEvent(p["event"])
	if !ok {
		return
	}
	withRemoteSession(p["session_id"], func(s *remoteDesktopSession) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = json.NewEncoder(s.in).Encode(e)
	})
}

func resizeRemoteDesktop(p map[string]string) {
	w, h, ok := remoteCaptureSize(p, linuxDesktopWidth, linuxDesktopHeight)
	if !ok {
		return
	}
	withRemoteSession(p["session_id"], func(s *remoteDesktopSession) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = json.NewEncoder(s.in).Encode(remoteHelperCommand{Type: "resize", Width: w, Height: h})
	})
}

func displayRemoteDesktop(map[string]string) {}

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
		if s.cmd != nil && s.cmd.Process != nil {
			_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGTERM)
			_, _ = s.cmd.Process.Wait()
		}
	})
}

func launchRemoteDesktopHelper(id string, nc *nats.Conn) (*remoteDesktopSession, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, "--remote-desktop-helper")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		_ = in.Close()
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		_ = in.Close()
		_ = out.Close()
		return nil, err
	}
	return &remoteDesktopSession{id: id, in: in, out: out, cmd: cmd, nc: nc}, nil
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

func linuxDesktopDependencies() error {
	var missing []string
	for _, name := range []string{"Xvfb", "xauth", "xterm", "import", "xdotool", "xclip"} {
		if _, err := exec.LookPath(name); err != nil {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		return fmt.Errorf("Linux remote desktop requires: %s", strings.Join(missing, ", "))
	}
	return nil
}

type linuxDesktop struct {
	display string
	auth    string
	dir     string
	xvfb    *exec.Cmd
	xterm   *exec.Cmd
}

func startLinuxDesktop() (*linuxDesktop, error) {
	if err := linuxDesktopDependencies(); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "qdt-remote-desktop-")
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	display := ""
	for n := 90; n <= 99; n++ {
		if _, err := os.Stat(fmt.Sprintf("/tmp/.X11-unix/X%d", n)); errors.Is(err, os.ErrNotExist) {
			display = ":" + strconv.Itoa(n)
			break
		}
	}
	if display == "" {
		cleanup()
		return nil, errors.New("no free private X11 display")
	}
	cookie := make([]byte, 16)
	if _, err = rand.Read(cookie); err != nil {
		cleanup()
		return nil, err
	}
	auth := filepath.Join(dir, "Xauthority")
	if out, err := exec.Command("xauth", "-f", auth, "add", display, ".", hex.EncodeToString(cookie)).CombinedOutput(); err != nil {
		cleanup()
		return nil, fmt.Errorf("xauth failed: %s", strings.TrimSpace(string(out)))
	}
	xvfb := exec.Command("Xvfb", display, "-screen", "0", "1920x1080x24", "-nolisten", "tcp", "-auth", auth)
	xvfb.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err = xvfb.Start(); err != nil {
		cleanup()
		return nil, err
	}
	d := &linuxDesktop{display: display, auth: auth, dir: dir, xvfb: xvfb}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err = os.Stat("/tmp/.X11-unix/X" + strings.TrimPrefix(display, ":")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			d.close()
			return nil, errors.New("Xvfb did not become ready")
		}
	}
	env := append(os.Environ(), "DISPLAY="+display, "XAUTHORITY="+auth, "HOME="+dir)
	xterm := exec.Command("xterm", "-geometry", "160x48+0+0", "-fa", "Monospace", "-fs", "12", "-title", "QDT Remote Terminal")
	xterm.Env = env
	xterm.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err = xterm.Start(); err != nil {
		d.close()
		return nil, err
	}
	d.xterm = xterm
	return d, nil
}

func (d *linuxDesktop) command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "DISPLAY="+d.display, "XAUTHORITY="+d.auth, "HOME="+d.dir)
	return cmd
}

func (d *linuxDesktop) close() {
	for _, cmd := range []*exec.Cmd{d.xterm, d.xvfb} {
		if cmd != nil && cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			_, _ = cmd.Process.Wait()
		}
	}
	_ = os.RemoveAll(d.dir)
}

func RunRemoteDesktopHelper(in io.Reader, out io.Writer) error {
	desktop, err := startLinuxDesktop()
	if err != nil {
		return err
	}
	defer desktop.close()
	enc := json.NewEncoder(out)
	var encMu sync.Mutex
	send := func(v map[string]interface{}) error { encMu.Lock(); defer encMu.Unlock(); return enc.Encode(v) }
	_ = send(map[string]interface{}{"action": "ready", "monitors": []remoteMonitor{{ID: 0, Name: "QDT Remote Terminal", Width: linuxDesktopWidth, Height: linuxDesktopHeight, Primary: true}}, "selected_monitor": 0})
	state := linuxDesktopState{width: 1280, height: 720}
	go readLinuxDesktopCommands(desktop, in, &state, send)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var seq uint64
	for range ticker.C {
		state.RLock()
		w, h := state.width, state.height
		state.RUnlock()
		// shortcut: one ImageMagick process per frame, replace when Linux desktop profiling warrants a persistent capturer.
		frame, err := desktop.command("import", "-window", "root", "-resize", fmt.Sprintf("%dx%d>", w, h), "-quality", "72", "jpeg:-").Output()
		if err != nil {
			return fmt.Errorf("desktop capture failed: %w", err)
		}
		if len(frame) == 0 || base64.StdEncoding.EncodedLen(len(frame)) > remoteMaxEncodedFrameSize {
			continue
		}
		seq++
		if err = send(map[string]interface{}{"action": "frame", "mime": "image/jpeg", "data": base64.StdEncoding.EncodeToString(frame), "seq": seq}); err != nil {
			return err
		}
	}
	return nil
}

func readLinuxDesktopCommands(d *linuxDesktop, in io.Reader, state *linuxDesktopState, send func(map[string]interface{}) error) {
	dec := json.NewDecoder(in)
	for {
		var command remoteHelperCommand
		if dec.Decode(&command) != nil {
			return
		}
		switch command.Type {
		case "resize":
			if command.Width >= 1 && command.Width <= linuxDesktopWidth && command.Height >= 1 && command.Height <= linuxDesktopHeight {
				state.Lock()
				state.width, state.height = command.Width, command.Height
				state.Unlock()
			}
		case "pointer", "wheel", "key":
			applyLinuxRemoteInput(d, command)
		case "shortcut":
			if keys := linuxShortcut(command.Name); keys != "" {
				_ = d.command("xdotool", "key", "--clearmodifiers", keys).Run()
			}
		case "clipboard_get":
			if value, err := d.command("xclip", "-selection", "clipboard", "-out").Output(); err == nil && validRemoteClipboardText(string(value)) {
				_ = send(map[string]interface{}{"action": "clipboard", "text": string(value)})
			}
		case "clipboard_set":
			if validRemoteClipboardText(command.Text) {
				cmd := d.command("xclip", "-selection", "clipboard", "-in")
				cmd.Stdin = strings.NewReader(command.Text)
				if cmd.Run() == nil {
					_ = send(map[string]interface{}{"action": "status", "state": "clipboard", "message": "updated"})
				}
			}
		}
	}

}

func applyLinuxRemoteInput(d *linuxDesktop, command remoteHelperCommand) {
	switch command.Type {
	case "pointer":
		x := strconv.Itoa(int(command.X * linuxDesktopWidth))
		y := strconv.Itoa(int(command.Y * linuxDesktopHeight))
		_ = d.command("xdotool", "mousemove", "--sync", x, y).Run()
		if command.Event == "pointerdown" || command.Event == "pointerup" {
			action := "mousedown"
			if command.Event == "pointerup" {
				action = "mouseup"
			}
			_ = d.command("xdotool", action, strconv.Itoa(command.Button+1)).Run()
		}
	case "wheel":
		button := "5"
		if command.DeltaY < 0 {
			button = "4"
		}
		_ = d.command("xdotool", "click", button).Run()
	case "key":
		key := linuxRemoteKey(command.Code)
		if key == "" {
			return
		}
		action := "keydown"
		if command.Event == "keyup" {
			action = "keyup"
		}
		_ = d.command("xdotool", action, key).Run()
	}
}

func linuxRemoteKey(code string) string {
	if len(code) == 4 && strings.HasPrefix(code, "Key") && code[3] >= 'A' && code[3] <= 'Z' {
		return strings.ToLower(code[3:])
	}
	if len(code) == 6 && strings.HasPrefix(code, "Digit") && code[5] >= '0' && code[5] <= '9' {
		return code[5:]
	}
	keys := map[string]string{"Enter": "Return", "Escape": "Escape", "Backspace": "BackSpace", "Tab": "Tab", "Space": "space", "ArrowUp": "Up", "ArrowDown": "Down", "ArrowLeft": "Left", "ArrowRight": "Right", "Delete": "Delete", "Home": "Home", "End": "End", "PageUp": "Page_Up", "PageDown": "Page_Down", "ShiftLeft": "Shift_L", "ShiftRight": "Shift_R", "ControlLeft": "Control_L", "ControlRight": "Control_R", "AltLeft": "Alt_L", "AltRight": "Alt_R", "MetaLeft": "Super_L", "MetaRight": "Super_R", "Minus": "minus", "Equal": "equal", "BracketLeft": "bracketleft", "BracketRight": "bracketright", "Backslash": "backslash", "Semicolon": "semicolon", "Quote": "apostrophe", "Backquote": "grave", "Comma": "comma", "Period": "period", "Slash": "slash"}
	return keys[code]
}

func linuxShortcut(name string) string {
	return map[string]string{"ctrl_shift_escape": "ctrl+shift+Escape", "alt_tab": "alt+Tab", "alt_f4": "alt+F4", "win_d": "super+d", "win_r": "super+r", "win_e": "super+e", "win_l": "super+l", "ctrl_alt_end": "ctrl+alt+End", "ctrl_c": "ctrl+c", "ctrl_v": "ctrl+v", "ctrl_x": "ctrl+x", "ctrl_a": "ctrl+a", "ctrl_z": "ctrl+z", "ctrl_y": "ctrl+y", "ctrl_s": "ctrl+s"}[name]
}
