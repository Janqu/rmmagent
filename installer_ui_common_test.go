package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestInstallerAPIBase(t *testing.T) {
	got, err := installerAPIBase("https://rmm.example.test/base/?x=1#top")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://rmm.example.test/base" {
		t.Fatalf("base %q", got)
	}
	for _, raw := range []string{"", "file:///tmp/x", "https://user:pass@example.test"} {
		if _, err := installerAPIBase(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestInstallerCommandArgs(t *testing.T) {
	got := installerCommandArgs(installerUIOptions{API: " https://rmm.example.test/ ", Token: " token ", Silent: true, Insecure: true})
	want := []string{"-m", "install", "-nomesh", "-api", "https://rmm.example.test/", "-auth", "token", "-silent", "-insecure"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args %#v", got)
	}
}

func TestFetchInstallerTokenInfo(t *testing.T) {
	var auth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if r.URL.Path != "/api/v3/installer/" {
			t.Fatalf("path %s", r.URL.Path)
		}
		fmt.Fprint(w, `{"site":9,"monitoring_type":"server","power":true,"rdp":false,"ping":true}`)
	}))
	defer server.Close()

	info, err := fetchInstallerTokenInfo(server.URL, "secret", false)
	if err != nil {
		t.Fatal(err)
	}
	if auth != "Token secret" || info.Site != 9 || info.MonitoringType != "server" || !info.Power || !info.Ping || info.RDP {
		t.Fatalf("auth=%q info=%#v", auth, info)
	}
}
