package agent

import "testing"

func TestNatsEndpoint(t *testing.T) {
	for _, tc := range []struct{ base, path, port, want string }{
		{"http://localhost:8088", "", "", "ws://localhost:8088"},
		{"https://rmm.example", "", "", "wss://rmm.example:443"},
		{"https://[::1]:8443", "custom", "9443", "wss://[::1]:9443"},
	} {
		got, path, _, _ := natsEndpoint(tc.base, "unused", tc.path, tc.port, "")
		if got != tc.want {
			t.Fatalf("got %s want %s", got, tc.want)
		}
		if tc.path != "" && path != tc.path {
			t.Fatal("custom path lost")
		}
	}
}
