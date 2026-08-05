package engine

import (
	"testing"

	"agent-cybersecurity-guardrails/config"
	"agent-cybersecurity-guardrails/detector"
	"agent-cybersecurity-guardrails/monitor"
	"agent-cybersecurity-guardrails/whitelist"
)

func setupEngine(t *testing.T) *Engine {
	t.Helper()
	cfg := config.DefaultConfig()
	wl := whitelist.New(cfg.Whitelist)
	ad := detector.New(&cfg.Behaviour)
	return New(cfg, wl, ad)
}

func TestEvaluateProcessWhitelisted(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Whitelist = []config.WhitelistEntry{{Path: "/usr/bin/ssh", SHA256: ""}}
	wl := whitelist.New(cfg.Whitelist)
	ad := detector.New(&cfg.Behaviour)
	engine := New(cfg, wl, ad)
	evt := monitor.ProcessEvent{Info: monitor.ProcessInfo{PID: 1234, Exe: "/usr/bin/ssh", CmdlineArr: []string{"/usr/bin/ssh", "user@host"}}}
	v := engine.EvaluateProcess(evt)
	if v.Decision != Allow {
		t.Errorf("expected ALLOW, got %s", v.Decision)
	}
}

func TestEvaluateProcessBlacklistedExecutable(t *testing.T) {
	engine := setupEngine(t)
	evt := monitor.ProcessEvent{Info: monitor.ProcessInfo{PID: 5678, Exe: "/tmp/malware", CmdlineArr: []string{"/tmp/malware"}}}
	v := engine.EvaluateProcess(evt)
	if v.Decision != Kill {
		t.Errorf("expected KILL, got %s", v.Decision)
	}
}

func TestEvaluateProcessBlacklistedArg(t *testing.T) {
	engine := setupEngine(t)
	evt := monitor.ProcessEvent{Info: monitor.ProcessInfo{PID: 9999, Exe: "/usr/bin/bash", CmdlineArr: []string{"/usr/bin/bash", "-c", "evil"}}}
	v := engine.EvaluateProcess(evt)
	if v.Decision != Kill {
		t.Errorf("expected KILL, got %s", v.Decision)
	}
}

func TestEvaluateProcessUnknown(t *testing.T) {
	engine := setupEngine(t)
	evt := monitor.ProcessEvent{Info: monitor.ProcessInfo{PID: 7777, Exe: "/usr/bin/unknown_app", CmdlineArr: []string{"/usr/bin/unknown_app"}}}
	v := engine.EvaluateProcess(evt)
	if v.Decision != Quarantine {
		t.Errorf("expected QUARANTINE, got %s", v.Decision)
	}
}

func TestEvaluateNetworkViolation(t *testing.T) {
	engine := setupEngine(t)
	evt := monitor.NetworkEvent{Connection: monitor.NetworkConnection{PID: 1234}, Reason: "blocked IP"}
	v := engine.EvaluateNetwork(evt)
	if v.Decision != Kill {
		t.Errorf("expected KILL, got %s", v.Decision)
	}
}

func TestEvaluateNetworkOK(t *testing.T) {
	engine := setupEngine(t)
	evt := monitor.NetworkEvent{Connection: monitor.NetworkConnection{PID: 1234}, Reason: ""}
	v := engine.EvaluateNetwork(evt)
	if v.Decision != Allow {
		t.Errorf("expected ALLOW, got %s", v.Decision)
	}
}

func TestIsBlacklistedPath(t *testing.T) {
	engine := setupEngine(t)
	if !engine.IsBlacklistedPath("/tmp/evil") {
		t.Error("expected /tmp/evil to be blacklisted")
	}
	if engine.IsBlacklistedPath("/usr/bin/ssh") {
		t.Error("expected /usr/bin/ssh to not be blacklisted")
	}
}

func TestCheckArgBlacklist(t *testing.T) {
	engine := setupEngine(t)
	found, blocked := engine.CheckArgBlacklist([]string{"normal", "-c", "cmd"})
	if !found {
		t.Error("expected blacklisted arg found")
	}
	if blocked != "-c" {
		t.Errorf("expected -c, got %q", blocked)
	}
}

func TestGetAllowedPorts(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Whitelist = []config.WhitelistEntry{{Path: "/usr/bin/docker", SHA256: "", AllowedPorts: []int{2375, 2376}}}
	wl := whitelist.New(cfg.Whitelist)
	ad := detector.New(&cfg.Behaviour)
	engine := New(cfg, wl, ad)
	ports := engine.GetAllowedPorts("/usr/bin/docker")
	if len(ports) != 2 {
		t.Errorf("expected 2 ports, got %d", len(ports))
	}
}

func TestGetProcessName(t *testing.T) {
	if GetProcessName("/usr/bin/docker") != "docker" {
		t.Error("expected docker")
	}
}

func TestDecisionString(t *testing.T) {
	if Allow.String() != "ALLOW" {
		t.Error("expected ALLOW")
	}
	if Kill.String() != "KILL" {
		t.Error("expected KILL")
	}
	if Quarantine.String() != "QUARANTINE" {
		t.Error("expected QUARANTINE")
	}
	if Decision(99).String() != "UNKNOWN" {
		t.Error("expected UNKNOWN")
	}
}
