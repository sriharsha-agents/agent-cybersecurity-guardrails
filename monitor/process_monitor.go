package monitor

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"agent-cybersecurity-guardrails/config"
)

// ProcessInfo contains information about a detected process.
type ProcessInfo struct {
	PID        int      `json:"pid"`
	PPID       int      `json:"ppid"`
	Name       string   `json:"name"`
	Exe        string   `json:"exe"`
	Cmdline    string   `json:"cmdline"`
	CmdlineArr []string `json:"cmdline_arr"`
	CPUTime    float64  `json:"cpu_percent"`
	MemoryRSS  uint64   `json:"memory_rss"`
	CreateTime float64  `json:"create_time"`
}

// ProcessEvent is emitted when a new or changed process is detected.
type ProcessEvent struct {
	Info      ProcessInfo `json:"info"`
	Timestamp time.Time   `json:"timestamp"`
}

// ProcessMonitor continuously scans for new processes and emits events.
type ProcessMonitor struct {
	cfg       *config.BehaviourConfig
	seenPIDs  map[int]bool
	mu        sync.Mutex
	eventChan chan<- ProcessEvent
	ticker    *time.Ticker
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewProcessMonitor creates a new ProcessMonitor.
func NewProcessMonitor(cfg *config.BehaviourConfig, eventChan chan<- ProcessEvent) *ProcessMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &ProcessMonitor{
		cfg:       cfg,
		seenPIDs:  make(map[int]bool),
		eventChan: eventChan,
		ticker:    time.NewTicker(1 * time.Second),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start begins the monitoring loop.
func (pm *ProcessMonitor) Start() {
	go pm.run()
}

// Stop stops the monitoring loop.
func (pm *ProcessMonitor) Stop() {
	pm.cancel()
	pm.ticker.Stop()
}

func (pm *ProcessMonitor) run() {
	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-pm.ticker.C:
			pm.scan()
		}
	}
}

// scan enumerates all running processes and emits events for new ones.
func (pm *ProcessMonitor) scan() {
	procs, err := pm.enumerateProcesses()
	if err != nil {
		log.Printf("[process_monitor] scan error: %v", err)
		return
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, p := range procs {
		if pm.seenPIDs[p.PID] {
			continue
		}
		pm.seenPIDs[p.PID] = true

		evt := ProcessEvent{
			Info:      p,
			Timestamp: time.Now(),
		}

		// Non-blocking send
		select {
		case pm.eventChan <- evt:
		default:
			log.Printf("[process_monitor] event channel full, dropping event for PID %d", p.PID)
		}
	}
}

// enumerateProcesses reads /proc to get process information.
// This is a simplified implementation; in production, use gopsutil or eBPF.
func (pm *ProcessMonitor) enumerateProcesses() ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	var procs []ProcessInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// PID is the directory name (numeric)
		pid := 0
		n, err := fmt.Sscanf(entry.Name(), "%d", &pid)
		if err != nil || n != 1 {
			continue
		}

		info, err := pm.readProcessInfo(pid)
		if err != nil {
			continue
		}

		procs = append(procs, info)
	}

	return procs, nil
}

// readProcessInfo reads info for a single PID from /proc.
func (pm *ProcessMonitor) readProcessInfo(pid int) (ProcessInfo, error) {
	info := ProcessInfo{PID: pid}

	// Read cmdline
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	if data, err := os.ReadFile(cmdlinePath); err == nil && len(data) > 0 {
		// cmdline is null-separated
		info.Cmdline = string(data)
		// Split by null bytes for array form
		for i, b := range data {
			if b == 0 {
				data[i] = ' '
			}
		}
		cmd := string(data)
		for len(cmd) > 0 && cmd[0] == ' ' {
			cmd = cmd[1:]
		}
		for len(cmd) > 0 && cmd[len(cmd)-1] == ' ' {
			cmd = cmd[:len(cmd)-1]
		}
		parts := splitArgs(cmd)
		info.CmdlineArr = parts
	}

	// Read exe (symlink to executable path)
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	if exe, err := os.Readlink(exePath); err == nil {
		info.Exe = exe
		info.Name = filepath.Base(exe)
	}

	// Read status for PPID and memory
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	if data, err := os.ReadFile(statusPath); err == nil {
		for _, line := range splitLines(string(data)) {
			if len(line) >= 6 {
				switch {
				case line[:5] == "PPid:":
					fmt.Sscanf(line[5:], "%d", &info.PPID)
				case line[:7] == "VmRSS:":
					var rssKB int64
					fmt.Sscanf(line[7:], "%d", &rssKB)
					info.MemoryRSS = uint64(rssKB * 1024)
				}
			}
		}
	}

	// Read stat for create time
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	if data, err := os.ReadFile(statPath); err == nil {
		content := string(data)
		// Find the closing parenthesis to skip comm field with parentheses
		for i := 0; i < len(content); i++ {
			if content[i] == ')' {
				// Fields after comm: state(1), ppid(2), pgrp(3), session(4), tty(5), tpgid(6), flags(7),
				// minflt(8), cminflt(9), majflt(10), cmajflt(11), utime(12), stime(13),
				// cutime(14), cstime(15), priority(16), nice(17), num_threads(19), itrealvalue(20),
				// starttime(21)
				fields := splitFields(content[i+2:])
				if len(fields) >= 22 {
					var starttimeTicks uint64
					fmt.Sscanf(fields[20], "%d", &starttimeTicks)
					// Convert ticks to seconds (assuming HZ=100)
					info.CreateTime = float64(starttimeTicks) / 100.0
				}
				break
			}
		}
	}

	return info, nil
}

// MarkPIDSeen marks a PID as seen (used after evaluation to avoid re-emitting).
func (pm *ProcessMonitor) MarkPIDSeen(pid int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.seenPIDs[pid] = true
}

// ForgetPID removes a PID from seen set (used when process dies).
func (pm *ProcessMonitor) ForgetPID(pid int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.seenPIDs, pid)
}

// splitArgs splits a command line into arguments.
func splitArgs(s string) []string {
	var args []string
	start := 0
	for i := 1; i < len(s); i++ {
		if s[i] == ' ' && s[i-1] == ' ' {
			if start < i-1 {
				args = append(args, s[start:i-1])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		args = append(args, s[start:])
	}
	return args
}

// splitLines splits a string into lines.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	return lines
}

// splitFields splits whitespace-separated fields.
func splitFields(s string) []string {
	var fields []string
	start := 0
	inField := false
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			if !inField {
				start = i
				inField = true
			}
		} else {
			if inField {
				fields = append(fields, s[start:i])
				inField = false
			}
		}
	}
	if inField {
		fields = append(fields, s[start:])
	}
	return fields
}
