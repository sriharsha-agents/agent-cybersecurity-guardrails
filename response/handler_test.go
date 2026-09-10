package response

import (
	"agent-cybersecurity-guardrails/config"
	"agent-cybersecurity-guardrails/engine"
	"testing"
)

func TestNew(t *testing.T) {
	cfg := &config.ResponseConfig{AlertEndpoint: "http://x"}
	h := New(cfg)
	if h == nil || h.cfg != cfg {
		t.Fatal("init failed")
	}
}

func TestHandleAllow(t *testing.T) {
	h := New(&config.ResponseConfig{})
	v := engine.Verdict{Decision: engine.Allow}
	err := h.Handle(1, "/bin/sh", "echo hi", "ok", v)
	if err != nil {
		t.Error(err)
	}
}

func TestHandleUnknown(t *testing.T) {
	h := New(&config.ResponseConfig{})
	v := engine.Verdict{Decision: engine.Decision(99)}
	err := h.Handle(1, "/bin/sh", "echo hi", "ok", v)
	if err == nil {
		t.Error("expected error")
	}
}

func TestKillInvalidPID(t *testing.T) {
	h := New(&config.ResponseConfig{})
	err := h.killProcess(0, "/bin/sh")
	if err == nil {
		t.Error("expected error")
	}
}

func TestAlertJSON(t *testing.T) {
	a := Alert{PID: 1, Exe: "x", Cmdline: "c", Reason: "r", Action: "a"}
	if a.PID != 1 {
		t.Error("wrong")
	}
}
