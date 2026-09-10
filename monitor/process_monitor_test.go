package monitor

import (
	"context"
	"testing"
	"time"

	"agent-cybersecurity-guardrails/config"
)

func newTestPM(c *config.BehaviourConfig) *ProcessMonitor {
	ch := make(chan ProcessEvent, 100)
	ctx, cancel := context.WithCancel(context.Background())
	return &ProcessMonitor{cfg: c, myPID: 0, seenPIDs: make(map[int]bool), eventChan: ch, ctx: ctx, cancel: cancel, ticker: time.NewTicker(time.Millisecond)}
}

func TestNewProcessMonitor(t *testing.T) {
	pm := newTestPM(&config.BehaviourConfig{})
	if pm == nil || pm.seenPIDs == nil {
		t.Fatal("init failed")
	}
}

func TestMarkPIDSeen(t *testing.T) {
	pm := newTestPM(&config.BehaviourConfig{})
	pm.MarkPIDSeen(123)
	if !pm.seenPIDs[123] {
		t.Error("expected seen")
	}
}

func TestForgetPID(t *testing.T) {
	pm := newTestPM(&config.BehaviourConfig{})
	pm.MarkPIDSeen(123)
	pm.ForgetPID(123)
	if pm.seenPIDs[123] {
		t.Error("expected forgotten")
	}
}

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		in  string
		out []string
	}{
		{"hello", []string{"hello"}},
		{"a  b", []string{"a", "b"}},
		{"", []string{}},
	}
	for _, tc := range tests {
		got := splitArgs(tc.in)
		if len(got) != len(tc.out) {
			t.Errorf("splitArgs(%q) len=%d want %d", tc.in, len(got), len(tc.out))
			continue
		}
		for i := range tc.out {
			if got[i] != tc.out[i] {
				t.Errorf("splitArgs(%q)[%d]=%q want %q", tc.in, i, got[i], tc.out[i])
			}
		}
	}
}

func TestSplitLines(t *testing.T) {
	tests := []struct {
		in  string
		out []string
	}{
		{"a\nb\n", []string{"a", "b", ""}},
		{"hello", []string{"hello"}},
		{"", []string{""}},
		{"a\nb\nc", []string{"a", "b", "c"}},
	}
	for _, tc := range tests {
		got := splitLines(tc.in)
		if len(got) != len(tc.out) {
			t.Errorf("splitLines(%q) len=%d want %d", tc.in, len(got), len(tc.out))
			continue
		}
		for i := range tc.out {
			if got[i] != tc.out[i] {
				t.Errorf("splitLines(%q)[%d]=%q want %q", tc.in, i, got[i], tc.out[i])
			}
		}
	}
}

func TestSplitFields(t *testing.T) {
	tests := []struct {
		in  string
		out []string
	}{
		{"a b c", []string{"a", "b", "c"}},
		{"hello", []string{"hello"}},
		{"a  b", []string{"a", "b"}},
		{"", []string{}},
		{"  a  ", []string{"a"}},
	}
	for _, tc := range tests {
		got := splitFields(tc.in)
		if len(got) != len(tc.out) {
			t.Errorf("splitFields(%q) len=%d want %d", tc.in, len(got), len(tc.out))
			continue
		}
		for i := range tc.out {
			if got[i] != tc.out[i] {
				t.Errorf("splitFields(%q)[%d]=%q want %q", tc.in, i, got[i], tc.out[i])
			}
		}
	}
}

func TestProcessMonitorStartStop(t *testing.T) {
	pm := newTestPM(&config.BehaviourConfig{})
	pm.Start()
	time.Sleep(10 * time.Millisecond)
	pm.Stop()
}
