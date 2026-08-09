package detector

import (
	"testing"
	"time"

	"agent-cybersecurity-guardrails/config"
	"agent-cybersecurity-guardrails/monitor"
)

func defaultBehaviourCfg() *config.BehaviourConfig {
	return &config.BehaviourConfig{
		CPUPercentThreshold:   90.0,
		MemoryMBThreshold:     1024.0,
		SustainedCPUPercent:   80.0,
		MaxChildProcesses:     50,
		MaxNetworkConnections: 100,
	}
}

func TestCheckProcessNoAnomaly(t *testing.T) {
	d := New(defaultBehaviourCfg())
	reason := d.CheckProcess(monitor.ProcessInfo{
		PID:       100,
		CPUTime:   10.0,
		MemoryRSS: 50 * 1024 * 1024,
	})
	if reason != "" {
		t.Errorf("expected no anomaly, got: %s", reason)
	}
}

func TestCheckProcessHighCPU(t *testing.T) {
	d := New(defaultBehaviourCfg())
	reason := d.CheckProcess(monitor.ProcessInfo{
		PID:       200,
		CPUTime:   95.0,
		MemoryRSS: 50 * 1024 * 1024,
	})
	if reason == "" {
		t.Error("expected CPU anomaly detected")
	}
}

func TestCheckProcessHighMemory(t *testing.T) {
	d := New(defaultBehaviourCfg())
	reason := d.CheckProcess(monitor.ProcessInfo{
		PID:       300,
		CPUTime:   10.0,
		MemoryRSS: 2048 * 1024 * 1024,
	})
	if reason == "" {
		t.Error("expected memory anomaly detected")
	}
}

func TestCheckProcessSustainedCPU(t *testing.T) {
	d := New(defaultBehaviourCfg())
	for i := 0; i < 10; i++ {
		d.CheckProcess(monitor.ProcessInfo{
			PID:       400,
			CPUTime:   85.0,
			MemoryRSS: 50 * 1024 * 1024,
		})
	}
	reason := d.CheckProcess(monitor.ProcessInfo{
		PID:       400,
		CPUTime:   85.0,
		MemoryRSS: 50 * 1024 * 1024,
	})
	if reason == "" {
		t.Error("expected sustained CPU anomaly detected")
	}
}

func TestRecordNetworkHitAndCheckAnomaly(t *testing.T) {
	cfg := defaultBehaviourCfg()
	cfg.MaxNetworkConnections = 5
	d := New(cfg)
	for i := 0; i < 6; i++ {
		d.RecordNetworkHit(500)
	}
	reason := d.CheckNetworkAnomaly(500)
	if reason == "" {
		t.Error("expected network anomaly detected")
	}
}

func TestCheckNetworkAnomalyWithinLimit(t *testing.T) {
	d := New(defaultBehaviourCfg())
	d.RecordNetworkHit(600)
	reason := d.CheckNetworkAnomaly(600)
	if reason != "" {
		t.Errorf("expected no network anomaly, got: %s", reason)
	}
}

func TestCleanup(t *testing.T) {
	d := New(defaultBehaviourCfg())
	d.CheckProcess(monitor.ProcessInfo{PID: 700, CPUTime: 10.0, MemoryRSS: 50 * 1024 * 1024})
	if len(d.lastSeen) != 1 {
		t.Error("expected 1 entry in lastSeen")
	}
	// Manually set timestamp to old
	d.lastSeen[700] = d.lastSeen[700].Add(-10 * time.Minute)
	d.Cleanup()
	if len(d.lastSeen) != 0 {
		t.Error("expected lastSeen to be empty after cleanup")
	}
}
