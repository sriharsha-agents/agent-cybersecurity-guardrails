package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if cfg.Response.Action != "kill" {
		t.Errorf("expected default action 'kill', got %q", cfg.Response.Action)
	}
	if cfg.Behaviour.CPUPercentThreshold != 80.0 {
		t.Errorf("expected default cpu_threshold 80.0, got %f", cfg.Behaviour.CPUPercentThreshold)
	}
	if len(cfg.Blacklist.Executables) == 0 {
		t.Error("expected default blacklist executables")
	}
}

func TestLoadValidConfig(t *testing.T) {
	yamlContent := `
whitelist:
  - path: "/usr/bin/test"
    sha256: "abc123"
blacklist:
  executables:
    - "/tmp/*"
  args:
    - "-e"
network:
  allowed_domains:
    - "*.example.com"
  blocklist_ips:
    - "10.0.0.1"
  max_connections_per_minute: 50
behaviour:
  cpu_threshold: 75.0
  memory_threshold: 1024.0
  scan_ips_threshold: 50
  sustained_cpu_percent: 60.0
  max_child_processes: 30
  max_network_connections: 100
response:
  action: "kill"
  alert_endpoint: "http://localhost:8080/alert"
  grace_period: "5s"
`
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "test.yaml")
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Behaviour.CPUPercentThreshold != 75.0 {
		t.Errorf("expected cpu_threshold 75.0, got %f", cfg.Behaviour.CPUPercentThreshold)
	}
	if len(cfg.Whitelist) != 1 {
		t.Errorf("expected 1 whitelist entry, got %d", len(cfg.Whitelist))
	}
	if cfg.Whitelist[0].SHA256 != "abc123" {
		t.Errorf("expected sha256 'abc123', got %q", cfg.Whitelist[0].SHA256)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestValidateInvalidCPUThreshold(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Behaviour.CPUPercentThreshold = 150.0
	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for cpu_threshold > 100")
	}
}

func TestValidateInvalidAction(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Response.Action = "invalid_action"
	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for invalid action")
	}
}

func TestValidateNegativeMemoryThreshold(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Behaviour.MemoryMBThreshold = -1.0
	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for negative memory_threshold")
	}
}
