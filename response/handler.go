package response

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"agent-cybersecurity-guardrails/config"
	"agent-cybersecurity-guardrails/engine"
)

// Alert represents a security alert sent to external systems.
type Alert struct {
	PID       int       `json:"pid"`
	Exe       string    `json:"exe"`
	Cmdline   string    `json:"cmdline"`
	Reason    string    `json:"reason"`
	Action    string    `json:"action"`
	Timestamp time.Time `json:"timestamp"`
}

// Handler executes the configured response action when a threat is detected.
type Handler struct {
	cfg *config.ResponseConfig
}

// New creates a new response Handler.
func New(cfg *config.ResponseConfig) *Handler {
	return &Handler{
		cfg: cfg,
	}
}

// Handle processes a verdict and executes the appropriate response.
func (h *Handler) Handle(pid int, exe, cmdline, reason string, verdict engine.Verdict) error {
	log.Printf("[response] PID=%d EXE=%s VERDICT=%s REASON=%s", pid, exe, verdict.Decision, reason)

	switch verdict.Decision {
	case engine.Kill:
		return h.killProcess(pid, exe)
	case engine.Quarantine:
		return h.quarantineProcess(pid, exe)
	case engine.Allow:
		return nil
	default:
		return fmt.Errorf("unknown verdict: %v", verdict.Decision)
	}
}

// killProcess sends SIGKILL to the process.
func (h *Handler) killProcess(pid int, exe string) error {
	if pid <= 0 {
		return fmt.Errorf("invalid PID %d", pid)
	}

	cmd := exec.Command("kill", "-9", fmt.Sprintf("%d", pid))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kill PID %d: %w (output: %s)", pid, err, string(output))
	}

	h.sendAlert(Alert{
		PID:       pid,
		Exe:       exe,
		Reason:    "killed",
		Action:    "kill",
		Timestamp: time.Now(),
	})

	log.Printf("[response] killed PID %d (%s)", pid, exe)
	return nil
}

// quarantineProcess copies the executable to a quarantine directory and kills the process.
func (h *Handler) quarantineProcess(pid int, exe string) error {
	// Copy to quarantine
	qDir := "/var/lib/guardrails/quarantine"
	if err := os.MkdirAll(qDir, 0700); err != nil {
		return fmt.Errorf("create quarantine dir: %w", err)
	}

	base := filepath.Base(exe)
	qPath := filepath.Join(qDir, fmt.Sprintf("%s_%d_%d", base, pid, time.Now().Unix()))

	in, err := os.Open(exe)
	if err != nil {
		// If we can't open the exe, just kill it
		return h.killProcess(pid, exe)
	}
	defer in.Close()

	out, err := os.OpenFile(qPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("create quarantine file: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy to quarantine: %w", err)
	}

	// Then kill the process
	if err := h.killProcess(pid, exe); err != nil {
		return err
	}

	h.sendAlert(Alert{
		PID:       pid,
		Exe:       exe,
		Reason:    fmt.Sprintf("quarantined to %s", qPath),
		Action:    "quarantine",
		Timestamp: time.Now(),
	})

	log.Printf("[response] quarantined PID %d (%s) -> %s", pid, exe, qPath)
	return nil
}

// sendAlert sends an alert to the configured endpoint.
func (h *Handler) sendAlert(alert Alert) {
	if h.cfg.AlertEndpoint == "" {
		return
	}

	payload, err := json.Marshal(alert)
	if err != nil {
		log.Printf("[response] marshal alert: %v", err)
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(h.cfg.AlertEndpoint, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("[response] send alert: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("[response] alert endpoint returned %d", resp.StatusCode)
	}
}
