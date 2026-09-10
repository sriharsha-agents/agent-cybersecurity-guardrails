package monitor

import (
	"agent-cybersecurity-guardrails/config"
	"context"
	"testing"
	"time"
)

func newTestNM(c *config.NetworkConfig) *NetworkMonitor {
	ch := make(chan NetworkEvent, 100)
	ctx, cancel := context.WithCancel(context.Background())
	return &NetworkMonitor{cfg: c, eventChan: ch, connTrack: make(map[string]int64), ctx: ctx, cancel: cancel, ticker: time.NewTicker(time.Millisecond)}
}

func TestNewNetworkMonitor(t *testing.T) {
	nm := newTestNM(&config.NetworkConfig{MaxConnections: 50})
	if nm == nil || nm.connTrack == nil {
		t.Fatal("init failed")
	}
}

func TestEval_Blocklisted(t *testing.T) {
	nm := newTestNM(&config.NetworkConfig{BlocklistIPs: []string{"1.2.3.4"}})
	if nm.evaluateConnection(NetworkConnection{RemoteIP: "1.2.3.4"}, time.Now().Unix()) == "" {
		t.Error("expected violation")
	}
}

func TestEval_Allowed(t *testing.T) {
	nm := newTestNM(&config.NetworkConfig{BlocklistIPs: []string{"1.2.3.4"}, MaxConnections: 50})
	if r := nm.evaluateConnection(NetworkConnection{RemoteIP: "5.6.7.8"}, time.Now().Unix()); r != "" {
		t.Error(r)
	}
}

func TestEval_RateLimit(t *testing.T) {
	nm := newTestNM(&config.NetworkConfig{MaxConnections: 1})
	now := time.Now().Unix()
	nm.connTrack["a"] = now
	nm.connTrack["b"] = now
	if nm.evaluateConnection(NetworkConnection{RemoteIP: "c"}, now) == "" {
		t.Error("expected rate limit")
	}
}

func TestDomainAllowed(t *testing.T) {
	nm := newTestNM(&config.NetworkConfig{AllowedDomains: []string{"*.co", "ex.com"}})
	if !nm.IsDomainAllowed("a.co") {
		t.Error("want true")
	}
	if nm.IsDomainAllowed("bad.com") {
		t.Error("want false")
	}
}

func TestWildcardMatch(t *testing.T) {
	if !wildcardMatch("*.a", "b.a") {
		t.Error("want true")
	}
	if wildcardMatch("*.a", "c") {
		t.Error("want false")
	}
}

func TestHexToIP(t *testing.T) {
	if hexToIP("0A000001") != "10.0.0.1" {
		t.Error("wrong")
	}
	if hexToIP("") != "" {
		t.Error("want empty")
	}
}

func TestParseTCPLine(t *testing.T) {
	_, err := parseTCPLine("bad")
	if err == nil {
		t.Error("want error")
	}
	c, err := parseTCPLine("0 0100007F:1F92 0100007F:0050 01 0 0 0 0 0 0 0")
	if err != nil {
		t.Error(err)
		return
	}
	if c.Protocol != "tcp" {
		t.Error("wrong protocol:", c.Protocol)
	}
	if c.Status != "ESTABLISHED" {
		t.Error("wrong status:", c.Status)
	}
	if c.RemotePort != 80 {
		t.Error("wrong port:", c.RemotePort)
	}
}

func TestStartStop(t *testing.T) {
	nm := newTestNM(&config.NetworkConfig{MaxConnections: 100})
	nm.Start()
	time.Sleep(10 * time.Millisecond)
	nm.Stop()
}
