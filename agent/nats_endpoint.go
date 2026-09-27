package agent

import (
	"net"
	"net/url"
)

func natsEndpoint(base, host, path, port, standardPort string) (string, string, string, bool) {
	scheme := "wss"
	u, err := url.Parse(base)
	if err == nil && u.Hostname() != "" {
		host = u.Hostname()
		if port == "" {
			port = u.Port()
		}
		if u.Scheme == "http" {
			scheme = "ws"
		}
	}
	if path == "" {
		path = "natsws"
	}
	if port == "" {
		if scheme == "ws" {
			port = "80"
		} else {
			port = "443"
		}
	}
	if standardPort != "" {
		return "tls://" + net.JoinHostPort(host, standardPort), path, port, false
	}
	return scheme + "://" + net.JoinHostPort(host, port), path, port, true
}
