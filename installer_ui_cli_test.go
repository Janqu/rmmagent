//go:build !fyne

package main

import (
	"bufio"
	"strings"
	"testing"
)

func TestPromptDefault(t *testing.T) {
	if got := promptDefault(bufio.NewReader(strings.NewReader("\n")), "Token", "existing"); got != "existing" {
		t.Fatalf("blank input should keep default, got %q", got)
	}
	if got := promptDefault(bufio.NewReader(strings.NewReader("new-token\n")), "Token", "existing"); got != "new-token" {
		t.Fatalf("input should override default, got %q", got)
	}
}
