package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// WhitelistEntry defines a trusted executable in the whitelist.
type WhitelistEntry struct {
	Path         string   `yaml:"path"`
	SHA256       string   `yaml:"sha256"`
	AllowedArgs  []string `yaml:"allowed_args,omitempty"`
	AllowedPorts []int    `yaml:"allowed_ports,omitempty"`
}

// BlacklistConfig defines patterns for blacklisted executables and arguments.
type BlacklistConfig struct {
	Executables []string `yaml:"executables"`
	Args        []string `yaml:"args"`
}

// NetworkConfig defines network-related policies.
type NetworkConfig struct {
	AllowedDomains []string `yaml:"allowed_domains"`
	BlocklistIPs   []string `yaml:"blocklist_ips"`
	MaxConnections int      `yaml:"max_connections_per_minute"`
}

// BehaviourConfig defines thresholds for behavioral anomaly detection.
type BehaviourConfig struct {
	CPUPercentThreshold   float64 `yaml:"cpu_threshold"`
	MemoryMBThreshold     float64 `yaml:"memory_threshold"`
	ScanIPsThreshold      int     `yaml:"scan_ips_threshold"`
	SustainedCPUPercent   float64 `yaml:"sustained_cpu_percent"`
	MaxChildProcesses     int     `yaml:"max_child_processes"`
	MaxNetworkConnections int     `yaml:"max_network_connections"`
}

// ResponseConfig defines how the guardrail responds to threats.
type ResponseConfig struct {
	Action        string        `yaml:"action"`
	AlertEndpoint string        `yaml:"alert_endpoint"`
	GracePeriod   time.Duration `yaml:"grace_period"`
}

// Config is the top-level configuration structure.
type Config struct {
	Whitelist []WhitelistEntry `yaml:"whitelist"`
	Blacklist BlacklistConfig  `yaml:"blacklist"`
	Network   NetworkConfig    `yaml:"network"`
	Behaviour BehaviourConfig  `yaml:"behaviour"`
	Response  ResponseConfig   `yaml:"response"`
}

// Load reads and parses a YAML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config yaml: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

// Validate checks the configuration for required fields and sensible defaults.
func (c *Config) Validate() error {
	if c.Behaviour.CPUPercentThreshold < 0 || c.Behaviour.CPUPercentThreshold > 100 {
		return fmt.Errorf("cpu_threshold must be between 0 and 100, got %f", c.Behaviour.CPUPercentThreshold)
	}

	if c.Behaviour.MemoryMBThreshold < 0 {
		return fmt.Errorf("memory_threshold must be non-negative, got %f", c.Behaviour.MemoryMBThreshold)
	}

	validActions := map[string]bool{
		"kill":       true,
		"quarantine": true,
	}
	if !validActions[c.Response.Action] {
		return fmt.Errorf("response action must be 'kill' or 'quarantine', got '%s'", c.Response.Action)
	}

	return nil
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() *Config {
	return &Config{
		Whitelist: []WhitelistEntry{},
		Blacklist: BlacklistConfig{
			Executables: []string{"/tmp/*", "/dev/shm/*"},
			Args:        []string{"-e", "sh", "-c"},
		},
		Network: NetworkConfig{
			AllowedDomains: []string{"*.internal.com"},
			BlocklistIPs:   []string{},
			MaxConnections: 100,
		},
		Behaviour: BehaviourConfig{
			CPUPercentThreshold: 80.0,
			MemoryMBThreshold:   200.0,
			ScanIPsThreshold:    100,
		},
		Response: ResponseConfig{
			Action:        "kill",
			AlertEndpoint: "",
			GracePeriod:   0,
		},
	}
}
