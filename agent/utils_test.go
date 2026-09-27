package agent

import (
	"strings"
	"testing"
)

func TestCappedBuffer(t *testing.T) {
	b := newCappedBuffer(4)

	n, err := b.Write([]byte("abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 6 {
		t.Fatalf("got %d bytes written, want 6", n)
	}
	if got := b.String(); !strings.Contains(got, "[output truncated]") {
		t.Fatalf("missing truncation marker in %q", got)
	}
	if got := b.buf.String(); got != "abcd" {
		t.Fatalf("got %q want abcd", got)
	}
}

func TestClampCommandTimeoutSeconds(t *testing.T) {
	if got := clampCommandTimeoutSeconds(0); got != defaultCommandTimeoutSeconds {
		t.Fatalf("got %d want %d", got, defaultCommandTimeoutSeconds)
	}
	if got := clampCommandTimeoutSeconds(maxCommandTimeoutSeconds + 1); got != maxCommandTimeoutSeconds {
		t.Fatalf("got %d want %d", got, maxCommandTimeoutSeconds)
	}
	if got := clampCommandTimeoutSeconds(42); got != 42 {
		t.Fatalf("got %d want 42", got)
	}
}

func TestValidatePayloadLimits(t *testing.T) {
	if err := validateCommandPayload(strings.Repeat("x", maxCommandBytes+1), nil, nil); err == nil {
		t.Fatal("oversized command accepted")
	}
	if err := validateScriptPayload(strings.Repeat("x", maxScriptBytes+1), nil, nil); err == nil {
		t.Fatal("oversized script accepted")
	}
	if err := validateCommandPayload("echo ok", []string{"arg"}, []string{"A=B"}); err != nil {
		t.Fatal(err)
	}
}

func TestTerminalSessionLimitReached(t *testing.T) {
	if terminalSessionLimitReached(maxTerminalSessions - 1) {
		t.Fatal("limit reached too early")
	}
	if !terminalSessionLimitReached(maxTerminalSessions) {
		t.Fatal("limit not reached")
	}
}

func TestDenoPermissionArgs(t *testing.T) {
	got, err := denoPermissionArgs(" --allow-read=/tmp   --deny-net --no-prompt ")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "--allow-read=/tmp --deny-net --no-prompt" {
		t.Fatalf("got %#v", got)
	}
	if _, err := denoPermissionArgs("--inspect"); err == nil {
		t.Fatal("unsupported deno arg accepted")
	}
	if _, err := denoPermissionArgs(strings.Repeat("--allow-read ", maxDenoPermissionArgs+1)); err == nil {
		t.Fatal("too many deno args accepted")
	}
}
