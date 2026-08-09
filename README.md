# Agent Cybersecurity Guardrails

A lightweight, high-performance Go daemon that enforces cybersecurity guardrails on Linux agents. It monitors process execution and network connections, evaluates them against configurable whitelist/blacklist policies and behavioral anomaly thresholds, and responds automatically by killing or quarantining threats.

## Features

- **Process Monitoring** – Observes new process spawns, command-line arguments, CPU usage, and memory consumption
- **Network Monitoring** – Tracks outbound connections, validates against allowed domains and blocklisted IPs
- **Whitelist Engine** – Trusted executables identified by path and optional SHA256 hash
- **Blacklist Engine** – Blocks executables in dangerous directories (`/tmp`, `/dev/shm`) and suspicious arguments (`-e`, `sh -c`)
- **Behavioral Anomaly Detection** – Detects CPU spikes, memory abuse, sustained high CPU, rapid child-process spawning, and excessive network connections
- **Automated Response** – Kills or quarantines offending processes, optionally sends alerts to an HTTP endpoint
- **YAML Configuration** – Simple, human-readable configuration file with sensible defaults

## Architecture

```
┌──────────────┐     ┌──────────────┐
│ Process Mon │     │ Network Mon │
└──────┬───────┘     └──────┬───────┘
     │                 │
     ▼                 ▼
┌────────────────────────────────┐
│        Decision Engine          │
│  (whitelist / blacklist / anomaly) │
└──────────────┬───────────────────┘
            │
            ▼
┌────────────────────────────────┐
│       Response Handler           │
│  (kill / quarantine / alert)    │
└────────────────────────────────┘
```

## Prerequisites

- **Go 1.21+**
- **Linux** (uses `/proc` filesystem for process monitoring)
- Root or CAP\_SYS\_KILL privileges (to kill processes)

## Installation

```bash
# Clone the repository
git clone https://github.com/h9945394143/agent-cybersecurity-guardrails.git
cd agent-cybersecurity-guardrails

# Download dependencies
go mod download

# Build
go build -o guardrails .
```

## Quick Start

```bash
# Run with default configuration
sudo ./guardrails

# Run with custom configuration file
sudo ./guardrails -config /etc/guardrails/guardrail.yaml
```

## Configuration

Copy the sample `guardrail.yaml` and adjust to your environment:

```yaml
# Whitelist: trusted executables
whitelist:
  - path: "/usr/bin/docker"
    sha256: ""
    allowed_args: []
    allowed_ports: [2375, 2376]
  - path: "/usr/bin/ssh"
    sha256: ""
    allowed_ports: [22]

# Blacklist: blocked executables and arguments
blacklist:
  executables:
    - "/tmp/*"
    - "/dev/shm/*"
  args:
    - "-e"
    - "sh -c"

# Network policies
network:
  allowed_domains:
    - "*.internal.com"
  blocklist_ips:
    - "10.66.66.0/24"
  max_connections_per_minute: 100

# Behavioral anomaly thresholds
behaviour:
  cpu_threshold: 80.0           # Kill if CPU > 80%
  memory_threshold: 2048.0      # Kill if memory > 2048 MB
  sustained_cpu_percent: 70.0   # Kill if avg CPU > 70% over 10 samples
  max_child_processes: 50      # Alert on fork-bomb patterns
  max_network_connections: 200 # Alert on connection floods

# Response action
response:
  action: "kill"              # "kill" or "quarantine"
  alert_endpoint: ""         # HTTP POST URL for alerts
  grace_period: "0s"         # Delay before action
```

### Configuration Reference

| Section     | Key                    | Type          | Description                                    |
|-----------|------------------------|---------------|------------------------------------------------|
| whitelist | `path`               | string        | Absolute path to the trusted executable           |
|         | `sha256`             | string        | Optional SHA256 hash for extra verification        |
|         | `allowed_ports`      | \[int\]       | Ports this executable is allowed to connect to     |
| blacklist | `executables`      | \[string\]    | Glob patterns of blocked executables              |
|         | `args`               | \[string\]    | Command-line arguments that trigger a block        |
| network   | `allowed_domains`    | \[string\]    | Allowed destination domains (wildcard supported)     |
|         | `blocklist_ips`    | \[string\]    | Blocked IP ranges (CIDR notation)                 |
|         | `max_connections_per_minute` | int | Rate-limit for connections          |
| behaviour | `cpu_threshold`    | float         | Single-sample CPU percentage threshold          |
|         | `memory_threshold`   | float         | Memory usage threshold in MB                  |
|         | `sustained_cpu_percent` | float       | Average CPU threshold over 10 samples           |
|         | `max_child_processes` | int          | Maximum children before fork-bomb alert        |
|         | `max_network_connections` | int     | Maximum network hits before anomaly alert        |
| response  | `action`             | string        | `"kill"` or `"quarantine"`                   |
|         | `alert_endpoint`   | string        | HTTP endpoint for alert notifications            |
|         | `grace_period`     | duration        | Delay before executing the response action        |

## Command-Line Flags

| Flag       | Default            | Description                        |
|-----------|-------------------|----------------------------------|
| `-config` | `guardrail.yaml` | Path to the YAML configuration file |

```bash
./guardrails -config /etc/guardrails/custom.yaml
```

## Decision Verdicts

| Verdict      | When Applied                                          |
|-------------|-------------------------------------------------------|
| `ALLOW`    | Process is whitelisted, no violations detected             |
| `KILL`    | Blacklisted executable/arg, network violation, or anomaly |
| `QUARANTINE` | Unknown process not in whitelist or blacklist        |

## Running as a Systemd Service

Create `/etc/systemd/system/guardrails.service`:

```ini
[Unit]
Description=Agent Cybersecurity Guardrails Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/guardrails -config /etc/guardrails/guardrail.yaml
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now guardrails
sudo systemctl status guardrails
```

## Testing

```bash
# Run all tests
go test ./... -v

# Run tests for a specific package
go test ./engine/... -v
```

## Project Structure

```
.
├── main.go                 # Daemon entry point
├── guardrail.yaml          # Sample configuration
├── config/                 # Configuration loader & validation
├── whitelist/              # Trusted executable store
├── engine/               # Decision engine (allow/kill/quarantine)
├── detector/             # Behavioral anomaly detection
├── monitor/              # Process & network event monitors
└── response/             # Response handler (kill/quarantine/alert)
```

## Licensing

This project is **Dual Licensed**.

- **Open Source (AGPL-3.0)**: Free for individuals, academic research, and small organizations with revenue < $1M/year. You may use, modify, and distribute the software, but any modifications must be open-sourced if you provide this as a network service.

- **Commercial License**: Required for enterprises with revenue > $1M/year, or for any organization that wishes to integrate this software into proprietary, closed-source products without releasing their source code.

👉 [Contact us for commercial licensing](mailto:sriharsha.manjunath@hotmail.com)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feat/amazing-feature`)
5. Open a Pull Request

## License

See [LICENSE](LICENSE) for AGPL-3.0 terms. Commercial licenses available upon request.
