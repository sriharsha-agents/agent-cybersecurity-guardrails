package detector

import (
	"fmt"
	"sync"
	"time"

	"agent-cybersecurity-guardrails/config"
	"agent-cybersecurity-guardrails/monitor"
)

// AnomalyDetector detects behavioral anomalies in processes.
type AnomalyDetector struct {
	cfg *config.BehaviourConfig
	mu  sync.Mutex
	// Track per-PID resource usage history
	cpuHistory    map[int][]float64
	memoryHistory map[int][]uint64
	networkHits   map[int]int // connections per PID in last minute
	lastSeen      map[int]time.Time
}

// New creates a new AnomalyDetector.
func New(cfg *config.BehaviourConfig) *AnomalyDetector {
	return &AnomalyDetector{
		cfg:           cfg,
		cpuHistory:    make(map[int][]float64),
		memoryHistory: make(map[int][]uint64),
		networkHits:   make(map[int]int),
		lastSeen:      make(map[int]time.Time),
	}
}

// CheckProcess evaluates a process for behavioral anomalies. Returns non-empty string if anomaly detected.
func (d *AnomalyDetector) CheckProcess(info monitor.ProcessInfo) string {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	// Update tracking
	d.cpuHistory[info.PID] = append(d.cpuHistory[info.PID], info.CPUTime)
	d.memoryHistory[info.PID] = append(d.memoryHistory[info.PID], info.MemoryRSS)
	d.lastSeen[info.PID] = now

	// Keep history bounded (last 60 samples)
	if len(d.cpuHistory[info.PID]) > 60 {
		d.cpuHistory[info.PID] = d.cpuHistory[info.PID][len(d.cpuHistory[info.PID])-60:]
	}
	if len(d.memoryHistory[info.PID]) > 60 {
		d.memoryHistory[info.PID] = d.memoryHistory[info.PID][len(d.memoryHistory[info.PID])-60:]
	}

	// Check CPU threshold
	if info.CPUTime > d.cfg.CPUPercentThreshold {
		return fmt.Sprintf("CPU usage %.1f%% exceeds threshold %.1f%%", info.CPUTime, d.cfg.CPUPercentThreshold)
	}

	// Check memory threshold (convert bytes to MB)
	memoryMB := float64(info.MemoryRSS) / (1024.0 * 1024.0)
	if memoryMB > d.cfg.MemoryMBThreshold {
		return fmt.Sprintf("Memory usage %.1fMB exceeds threshold %.1fMB", memoryMB, d.cfg.MemoryMBThreshold)
	}

	// Check sustained high CPU (average of last 10 samples)
	if cpuSamples, ok := d.cpuHistory[info.PID]; ok && len(cpuSamples) >= 10 {
		var sum float64
		for _, v := range cpuSamples[len(cpuSamples)-10:] {
			sum += v
		}
		avg := sum / 10.0
		if avg > d.cfg.SustainedCPUPercent {
			return fmt.Sprintf("Sustained CPU avg %.1f%% exceeds threshold %.1f%%", avg, d.cfg.SustainedCPUPercent)
		}
	}

	// Check rapid child spawning
	if info.PPID > 0 {
		// Count how many processes share this PPID in recent history
		childCount := 0
		for pid, ts := range d.lastSeen {
			if pid != info.PID && now.Sub(ts) < 60*time.Second {
				childCount++
			}
		}
		if childCount > d.cfg.MaxChildProcesses && d.cfg.MaxChildProcesses > 0 {
			return fmt.Sprintf("Rapid child spawning: %d children exceeds limit %d", childCount, d.cfg.MaxChildProcesses)
		}
	}

	return ""
}

// RecordNetworkHit records a network connection for a PID.
func (d *AnomalyDetector) RecordNetworkHit(pid int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.networkHits[pid]++
}

// CheckNetworkAnomaly checks if a PID has excessive network connections.
func (d *AnomalyDetector) CheckNetworkAnomaly(pid int) string {
	d.mu.Lock()
	defer d.mu.Unlock()

	hits := d.networkHits[pid]
	if hits > d.cfg.MaxNetworkConnections && d.cfg.MaxNetworkConnections > 0 {
		return fmt.Sprintf("Excessive network connections: %d exceeds limit %d", hits, d.cfg.MaxNetworkConnections)
	}
	return ""
}

// Cleanup removes stale entries older than 5 minutes.
func (d *AnomalyDetector) Cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-5 * time.Minute)

	for pid, ts := range d.lastSeen {
		if ts.Before(cutoff) {
			delete(d.lastSeen, pid)
			delete(d.cpuHistory, pid)
			delete(d.memoryHistory, pid)
			delete(d.networkHits, pid)
		}
	}
}
