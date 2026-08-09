# Agent Cybersecurity Guardrail: Context & Implementation Guide

## 1. Introduction

Modern systems often execute autonomous agents—AI models, automated scripts, microservices, or third‑party binaries—inside sandboxes or production servers. These agents can become compromised or behave maliciously, either due to vulnerabilities, supply‑chain attacks, or intentional rogue behaviour (e.g., a malicious OpenAI agent that breached a startup and attempted lateral movement to other firms).

This document defines a **robust guardrail system** that:

- **Secures** any sandbox or server from unauthorised external agents.
- **Detects** unknown agents upon entry using fingerprinting, behavioural analysis, and anomaly detection.
- **Automatically responds** by identifying the process, killing it, and alerting security teams.

The guardrail is designed to be lightweight, scalable, and adaptable to both containerised (Docker/Kubernetes) and VM/bare‑metal environments.

---

## 2. Threat Model

### 2.1. Assets
- Host OS and kernel.
- Sandboxed application processes and data.
- Internal network services and APIs.
- Secrets, credentials, and configuration.

### 2.2. Attack Vectors
- **Rogue Agent Injection**: An attacker uploads or injects a malicious agent into the runtime environment (e.g., via a compromised CI/CD pipeline, exposed API, or supply‑chain dependency).
- **Lateral Movement**: A compromised agent attempts to scan internal networks, exfiltrate data, or escalate privileges to other hosts.
- **Persistence Mechanisms**: The agent installs backdoors, schedules cron jobs, or modifies system files to survive restarts.
- **Resource Abuse**: CPU/memory exhaustion, cryptocurrency mining, or DoS attacks against other services.

### 2.3. Assumptions
- The guardrail runs with sufficient privileges (e.g., root or CAP_SYS_ADMIN) to monitor and kill processes.
- The host has a trusted base image (golden image) and a known‑good process baseline.
- Security events are sent to a central SIEM or logging system for further analysis.

---

## 3. Requirements

### 3.1. Functional Requirements
| ID   | Description |
|------|-------------|
| **FR-1** | Continuously monitor all running processes, containers, and child processes. |
| **FR-2** | Maintain a **whitelist** of known/trusted processes (by hash, path, or signature). |
| **FR-3** | Detect newly spawned processes that do not match the whitelist or exhibit suspicious behaviour (e.g., network connection to unknown external IP, high CPU, file system changes). |
| **FR-4** | Immediately **terminate** (SIGKILL) any unauthorised process and optionally quarantine the container/VM. |
| **FR-5** | Log all detection events with full context (PID, parent, command line, network sockets, file access). |
| **FR-6** | Support **real‑time** response (latency < 500 ms from detection to action). |
| **FR-7** | Allow manual override or temporary whitelisting for legitimate new agents. |
| **FR-8** | Integrate with orchestration platforms (Kubernetes admission controllers, Docker events) to block unauthorised container starts. |

### 3.2. Non‑Functional Requirements
| ID   | Description |
|------|-------------|
| **NFR-1** | Minimal performance overhead (< 5% CPU, < 100 MB RAM). |
| **NFR-2** | Must be resilient to guardrail process crashes (restart automatically). |
| **NFR-3** | Support Linux (x86_64, ARM64) and Windows (optional). |
| **NFR-4** | Provide audit trails for compliance (GDPR, SOC2). |
| **NFR-5** | Ability to run in **air‑gapped** or offline environments (no external dependencies except local signature DB). |

---

## 4. High‑Level Architecture
+---------------------+ +---------------------------+
| Orchestrator | | Guardrail Management |
| (K8s/Docker/Swarm) +------->+ API / Dashboard |
+---------------------+ +-------------+-------------+
|
v
+---------------------------------------------+---------------------------+
| Host / Sandbox Environment |
| +-------------------------------------------------------------------+ |
| | Agent Process (unknown) | |
| +-------------------------------------------------------------------+ |
| |
| +-------------------------------------------------------------------+ |
| | Guardrail Daemon (systemd / container sidecar) | |
| | - Process Monitor (psutil, /proc) | |
| | - Network Filter (eBPF / netfilter) | |
| | - Integrity Watcher (fanotify / inotify) | |
| | - Decision Engine (rules + ML) | |
| | - Response Handler (kill, isolate, alert) | |
| +-------------------------------------------------------------------+ |
| |
| +-------------------------------------------------------------------+ |
| | Local Whitelist DB (signed hashes + policies) | |
| +-------------------------------------------------------------------+ |
+-------------------------------------------------------------------------+
|
v
+---------------------------------+
| Central SIEM / Alerting |
| (Elastic, Splunk, TheHive) |
+---------------------------------+


### 4.1. Components Description

1. **Process Monitor**  
   - Uses `psutil` or `/proc` to enumerate processes every second.  
   - Tracks PID, PPID, command line, executable path, environment variables.  
   - Captures new process creation events via `fork`/`exec` hooks (Linux `perf_event_open` or eBPF `tracepoint`).

2. **Network Monitor**  
   - Inline eBPF probes or `netfilter` hooks to inspect outgoing connections.  
   - Flags connections to untrusted IP ranges (e.g., TOR, known malicious ASNs).  
   - Detects port scanning or unusual protocols.

3. **Filesystem & Integrity Watcher**  
   - Uses `inotify`/`fanotify` to watch critical directories (`/bin`, `/etc`, `/tmp`).  
   - Detects writes to sensitive files or creation of new executables.

4. **Whitelist & Policy Engine**  
   - Stores SHA‑256 hashes of authorised executables, signed by internal CA.  
   - Supports path‑based policies (e.g., allow `/usr/bin/*` but block `/tmp/*`).  
   - Dynamic learning mode: during a “training” period, the system can learn normal behaviour and generate a baseline.

5. **Behavioural Anomaly Detector**  
   - Uses statistical models (mean, stddev of CPU/memory/network over time).  
   - Optionally integrates a lightweight ML classifier (e.g., Isolation Forest) for zero‑day detection.

6. **Response Handler**  
   - On detection: kill process (`SIGKILL`), optionally pause the container (via cgroup freezer).  
   - Notify the central SIEM via syslog or REST API.  
   - If the parent is a container runtime, the guardrail can ask the orchestrator to delete the pod/container.

7. **Management API**  
   - Accepts whitelist updates, policy changes, and manual overrides.  
   - Exposes metrics for Prometheus (number of alerts, false‑positive rate).

---

## 5. Implementation Details

### 5.1. Tech Stack
- **Language**: Python 3.9+ (rapid prototyping) + C for eBPF helpers.  
- **Libraries**: `psutil`, `pyinotify`, `bcc` (eBPF), `requests`, `pyyaml`.  
- **Storage**: SQLite local cache, with optional sync to a remote database.  
- **Deployment**: Systemd service (VM) or Kubernetes DaemonSet (sidecar).

### 5.2. Process Monitoring (Python Skeleton)

```python
import psutil
import time
import hashlib
from threading import Thread

class ProcessMonitor:
    def __init__(self, whitelist_db, decision_engine):
        self.whitelist = whitelist_db
        self.decision = decision_engine
        self.seen_pids = set()

    def scan(self):
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'create_time']):
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                if pid in self.seen_pids:
                    continue
                # New process detected
                self.seen_pids.add(pid)
                self.evaluate(proc, pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def evaluate(self, proc, pinfo):
        # Check whitelist by executable hash
        exe_path = pinfo['exe']
        if exe_path and self.whitelist.is_trusted(exe_path):
            return
        # If not in whitelist, trigger decision
        decision = self.decision.decide(proc, pinfo)
        if decision == 'KILL':
            self.response_handler.kill(proc.pid)
            self.alert(f"Unauthorised process: {pinfo['cmdline']}")


5.3. Whitelist Database
Store a list of allowed executable hashes with metadata (owner, expiration, comments).
Update via signed YAML files:


whitelist:
  - path: /usr/bin/python3
    sha256: "a3b4c5d6..."
    allowed_args: ["-c", "allowed_script.py"]
  - path: /usr/bin/nginx
    sha256: "e7f8..."
    allowed_ports: [80, 443]

5.4. eBPF for Fast Detection
Using bcc to trace execve syscalls:

from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    bpf_trace_printk("exec %s\\n", args->filename);
    return 0;
}
"""
b = BPF(text=bpf_text)
b.trace_print()

5.5. Network Egress Filtering
Use iptables + nfqueue (or eBPF cgroup hooks) to intercept all outbound connections.
If a process is unauthorised, we can drop the packet and kill the process.

Alternative: use conntrack to monitor established connections and flag unexpected external IPs.


import os
import signal
import subprocess

class ResponseHandler:
    def kill_process(self, pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        # Optionally, kill entire process tree
        p = subprocess.Popen(['pkill', '-P', str(pid)], stdout=subprocess.DEVNULL)

    def quarantine_container(self, container_id):
        # For Docker
        subprocess.run(['docker', 'pause', container_id])
        # Or use cgroup freezer directly


6. Detection Rules
6.1. Whitelist Violation
Any executable not in the whitelist with a known hash is immediately killed (default‑deny).

6.2. Suspicious Command Line
Contains strings like curl, wget with | bash, or base64‑encoded payloads.

Regular expression matching against a blacklist.

6.3. Network Anomalies
Outbound connection to a country or ASN not in the business‑required set.

Connection to IP ranges known for C2 (e.g., from threat intelligence feeds).

Rapid connection attempts (> 100 distinct IPs per minute) → port scan.

6.4. Resource Hogging
CPU usage > 80% for more than 2 minutes (or multiple cores pinned).

Memory growth > 2× baseline in 30 seconds.

6.5. File System Modifications
New executable files created in /tmp or /dev/shm.

Modification of /etc/passwd, /etc/shadow, /etc/sudoers.

7. Deployment & Integration
7.1. As a Systemd Service (Bare Metal / VM)

[Unit]
Description=Agent Cybersecurity Guardrail
After=network.target

[Service]
ExecStart=/opt/guardrail/guardrail_daemon.py
Restart=always
RestartSec=5
CPUQuota=20%
MemoryLimit=256M
ProtectSystem=strict
ReadWritePaths=/var/log/guardrail

[Install]
WantedBy=multi-user.target

7.2. As a Kubernetes DaemonSet (Sidecar)
Use DaemonSet with a privileged security context to access host /proc and run eBPF.
The guardrail can also act as an admission webhook to block pod creation if the image is untrusted.

7.3. Integration with CI/CD
All new images must have their executables hashed and registered in the whitelist during build.

A pre‑commit hook ensures that any unknown binary is flagged before deployment.

8. Testing & Validation
8.1. Unit Tests
Mock psutil to simulate process lists.

Test whitelist matching and decision logic.

8.2. Integration Tests
Deploy a test container with a known malicious binary (e.g., stress simulating crypto mining).

Verify that the guardrail kills it within 1 second.

Test false‑positive scenarios (e.g., a legitimate new version of an agent with an updated hash → should be allowed after whitelist update).

8.3. Performance Benchmarks
Measure CPU/memory overhead under load (simulate 1000 processes).

Ensure response latency < 100 ms for execve events.

8.4. Chaos Engineering
Randomly spawn unknown processes and ensure they are terminated.

Kill the guardrail process; ensure it auto‑restarts.

9. Example: Rogue OpenAI Agent Scenario
Scenario: A startup runs an API that loads an OpenAI‑based agent. The agent is compromised (via a malicious plugin) and attempts to attack other firms by scanning internal networks and exfiltrating data.

Guardrail Response:

Process Monitor detects a new child process /tmp/evil_script.py (unknown hash) spawned by the agent.

Network Monitor observes it trying to connect to 198.51.100.0 (suspicious external IP).

Decision Engine triggers a kill action.

Response Handler sends SIGKILL to evil_script.py and logs a high‑severity alert.

The orchestrator is notified to restart the agent in a clean state.

Result: Lateral movement is blocked; other firms remain safe.

10. Maintenance & Tuning
False‑Positive Reduction: Use a learning mode to build a baseline over 24 hours, then enable enforcement.

Whitelist Updates: Provide a secure channel (e.g., signed S3 buckets) to push new hashes.

Logging: Rotate logs daily and send alerts to a SIEM for correlation.

11. Future Extensions
Behavioural ML: Integrate a lightweight LSTM model to detect subtle anomalies over time.

RASP (Runtime Application Self‑Protection): Embed guardrail hooks directly into the agent process via LD_PRELOAD.

Zero‑Trust Network: Combine with micro‑segmentation (e.g., Cilium policies) to enforce network micro‑perimeters.

12. Conclusion
The Agent Cybersecurity Guardrail provides a multi‑layered defence against rogue agents. By combining whitelisting, real‑time monitoring, and automated response, it ensures that any unauthorised process is swiftly identified and terminated—protecting both the local sandbox and the wider enterprise ecosystem.

This guardrail is a cornerstone of a Zero‑Trust runtime security posture, essential for any organisation running autonomous or third‑party agents.


Building the Guardrail in Go: Implementation Guide
The architectural blueprint above is language‑agnostic. This section provides a concrete, production‑ready implementation using Go – delivering high performance, low overhead, and robust system integration.

1. Why Go for This Guardrail?
Criterion	Go Advantage
Performance	Compiled to native code; goroutines enable concurrent monitoring without heavy threading overhead.
System Access	Direct syscall and os packages, plus excellent C‑interop for eBPF.
Memory Safety	Garbage‑collected, no buffer overflows – critical for security software.
Deployment	Single static binary – easy to distribute and run in containers or VMs.
Rich Ecosystem	Mature libraries for eBPF (cilium/ebpf), process monitoring (gopsutil), networking (netlink, gopacket).

import (
    // System & process
    "os"
    "syscall"
    "github.com/shirou/gopsutil/v3/process"
    
    // eBPF
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
    
    // Networking
    "github.com/vishvananda/netlink"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    
    // Configuration & logging
    "gopkg.in/yaml.v3"
    "github.com/sirupsen/logrus"
    
    // Metrics
    "github.com/prometheus/client_golang/prometheus"
)



+-----------------------------------------------------------+
|  Guardrail Daemon (main.go)                               |
|  - Signal handling (SIGTERM, SIGHUP)                     |
|  - Configuration loader                                   |
|  - Component initialisation (monitors, engine, response) |
+-------------------+---------------------------------------+
                    |
       +------------+-------------+
       |                           |
+------v------+           +--------v--------+
| Process     |           | Network         |
| Monitor     |           | Monitor         |
| (gopsutil + |           | (netlink +      |
|  eBPF)      |           |  eBPF)          |
+------+------+           +--------+--------+
       |                           |
       +------------+-------------+
                    |
+-------------------v-------------------+
|   Event Aggregator (channels)         |
|   - process_create_events             |
|   - net_connect_events                |
+-------------------+-------------------+
                    |
+-------------------v-------------------+
|   Decision Engine (goroutine)         |
|   - Whitelist check                   |
|   - Rule evaluation                   |
|   - Behavioural scoring               |
+-------------------+-------------------+
                    |
+-------------------v-------------------+
|   Response Handler                    |
|   - Kill process tree                 |
|   - Pause container (cgroup)          |
|   - Alert via syslog/HTTP             |
+---------------------------------------+


All components run as goroutines; events flow through buffered channels to decouple detection from reaction.

4. Process Monitor Implementation
import "github.com/shirou/gopsutil/v3/process"

func (pm *ProcessMonitor) Scan() error {
    procs, err := process.Processes()
    if err != nil {
        return err
    }
    for _, p := range procs {
        pid := p.Pid
        if _, seen := pm.seen[pid]; seen {
            continue
        }
        pm.seen[pid] = struct{}{}
        // Get details
        name, _ := p.Name()
        exe, _ := p.Exe()
        cmdline, _ := p.CmdlineSlice()
        // Evaluate
        pm.evaluate(pid, exe, cmdline)
    }
    return nil
}


4.2. Real‑time via eBPF (Recommended)
Use cilium/ebpf to attach to sys_enter_execve tracepoint for immediate process creation events.

eBPF C program (execve.c):

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *args) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    // Send PID and command to userspace ring buffer
    bpf_printk("execve: %s pid %d\n", comm, bpf_get_current_pid_tgid() >> 32);
    return 0;
}


Go loader:

func loadEBPF() (*ebpf.Program, link.Link, error) {
    // Remove rlimit
    rlimit.RemoveMemlock()

    spec, err := ebpf.LoadCollectionSpec("execve.o") // compiled .o
    if err != nil {
        return nil, nil, err
    }
    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        return nil, nil, err
    }
    prog := coll.Programs["trace_execve"]
    tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
    return prog, tp, err
}


Events are read from the trace pipe or via a ring buffer map (more efficient) – use perf.EventReader to receive notifications.

4.3. Monitoring Goroutine
func (pm *ProcessMonitor) Run() {
    ticker := time.NewTicker(1 * time.Second)
    for {
        select {
        case <-ticker.C:
            pm.Scan() // Fallback full scan
        case evt := <-pm.ebpfChan: // eBPF events
            pm.evaluate(evt.Pid, evt.Exe, evt.Args)
        }
    }
}


5. Network Monitor
5.1. Outbound Connection Interception with eBPF
Attach a cgroup‑socket‑connect hook (requires cgroup v2). This allows filtering outgoing connect() calls.

eBPF:

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx) {
    // Get PID
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    // Check if PID is blacklisted or suspicious
    // Optionally, allow only specific destinations
    if (is_unauthorized(pid, ctx->user_ip4, ctx->user_port)) {
        return 0; // block connection
    }
    return 1; // allow
}


Go attachment:

// Attach to the cgroup of the container or host
cgroupPath := "/sys/fs/cgroup/system.slice/guardrail.service"
cgroup, err := os.Open(cgroupPath)
if err != nil { ... }
defer cgroup.Close()

prog, err := ebpf.LoadProgram(...)
linker, err := link.AttachCgroup(link.CgroupOptions{
    Path:    cgroupPath,
    Attach:  ebpf.AttachCGroupInet4Connect,
    Program: prog,
})

For environments without cgroup v2, use netlink to read connection tracking (conntrack) and flag anomalous connections.


5.2. Passive Monitoring with gopacket
Capture packets on the host interface and inspect for suspicious flows (DNS, beaconing). Use pcap in non‑promiscuous mode.

func capturePackets(iface string) {
    handle, err := pcap.OpenLive(iface, 1600, false, pcap.BlockForever)
    // ...
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        // Inspect TCP/UDP, check destination IP against blocklist
    }
}


6. Whitelist & Policy Engine
6.1. Data Structures
type WhitelistEntry struct {
    Path      string   `yaml:"path"`
    SHA256    string   `yaml:"sha256"`
    AllowedArgs []string `yaml:"allowed_args,omitempty"`
}

type Config struct {
    Whitelist []WhitelistEntry `yaml:"whitelist"`
    Blacklist struct {
        Executables []string `yaml:"executables"`
        Args        []string `yaml:"args"`
    } `yaml:"blacklist"`
}


6.2. Concurrent Safe Store
type WhitelistStore struct {
    mu     sync.RWMutex
    byPath map[string]WhitelistEntry
    byHash map[string]WhitelistEntry
}

func (s *WhitelistStore) IsTrusted(path, hash string, args []string) bool {
    s.mu.RLock()
    defer s.mu.RUnlock()
    // Check hash first
    if entry, ok := s.byHash[hash]; ok {
        return s.matchArgs(entry, args)
    }
    // Check path (allow if path matches and hash either matches or is unverified)
    if entry, ok := s.byPath[path]; ok {
        if entry.SHA256 == "" || entry.SHA256 == hash {
            return s.matchArgs(entry, args)
        }
    }
    return false
}

6.3. Decision Engine
func (de *DecisionEngine) Decide(pid int, path string, args []string) Decision {
    // 1. Whitelist check
    if de.whitelist.IsTrusted(path, hash, args) {
        return Allow
    }
    // 2. Blacklist pattern match
    if de.blacklist.Matches(args) {
        return Kill
    }
    // 3. Behavioural anomalies (CPU/memory/network)
    if de.anomalyDetector.IsSuspicious(pid) {
        return Kill
    }
    // 4. Default deny
    return Kill
}

7. Response Handler (Go)

import "syscall"

func (rh *ResponseHandler) KillProcess(pid int) error {
    // Kill entire process tree
    pgid, err := syscall.Getpgid(pid)
    if err == nil {
        // Negative PGID sends signal to all in process group
        return syscall.Kill(-pgid, syscall.SIGKILL)
    }
    // Fallback: kill just this process
    return syscall.Kill(pid, syscall.SIGKILL)
}

// For container environments:
func (rh *ResponseHandler) PauseContainer(containerID string) {
    // Docker pause
    cmd := exec.Command("docker", "pause", containerID)
    cmd.Run()
    // Or use cgroup freezer: write "FROZEN" to /sys/fs/cgroup/freezer/.../freezer.state
}


8. Configuration (YAML)
guardrail.yaml:

whitelist:
  - path: /usr/bin/python3
    sha256: "a1b2c3..."
  - path: /usr/bin/nginx
    sha256: "d4e5f6..."
blacklist:
  executables: ["/tmp/*", "/dev/shm/*"]
  args: ["-e", "sh", "-c"]
network:
  allowed_domains: ["*.internal.com"]
  blocklist_ips: ["198.51.100.0/24"]
behaviour:
  cpu_threshold: 80    # percent
  memory_threshold: 200 # MB above baseline
response:
  action: "kill"        # or "quarantine"
  alert_endpoint: "http://siem.internal/events"



9. Main Program Orchestration
func main() {
    // Load config
    cfg := loadConfig("guardrail.yaml")
    // Init components
    wl := NewWhitelistStore(cfg.Whitelist)
    engine := NewDecisionEngine(wl, cfg.Blacklist, cfg.Behaviour)
    handler := NewResponseHandler(cfg.Response)

    // Start monitors
    pm := NewProcessMonitor(engine, handler)
    go pm.Run()

    nm := NewNetworkMonitor(cfg.Network, engine, handler)
    go nm.Run()

    // Signal handling for graceful shutdown
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
    <-sigChan
    // Clean up eBPF resources, etc.
}

10. Building & Deployment
10.1. Build the eBPF objects

# Compile eBPF C code
clang -O2 -g -target bpf -c execve.c -o execve.o

10.2. Build the Go binary
go mod tidy
GOOS=linux GOARCH=amd64 go build -o guardrail .


10.3. Run as Systemd Service
Same as in the blueprint but point to the binary.

10.4. Run as Kubernetes DaemonSet (Privileged)
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: guardrail
spec:
  selector:
    matchLabels:
      app: guardrail
  template:
    metadata:
      labels:
        app: guardrail
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: guardrail
        image: guardrail:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: proc
          mountPath: /host/proc
        - name: sys
          mountPath: /sys
        - name: cgroup
          mountPath: /sys/fs/cgroup
      volumes:
      - name: proc
        hostPath:
          path: /proc
      - name: sys
        hostPath:
          path: /sys
      - name: cgroup
        hostPath:
          path: /sys/fs/cgroup

11. Testing in Go
11.1. Mocking Dependencies
Use interfaces for process scanning and decision engines, then inject mocks in tests.


type ProcessFetcher interface {
    Processes() ([]*process.Process, error)
}
// In tests, use a mock that returns known processes.


11.2. Integration Test with Docker

# Start a container with a benign process
docker run -d --name test-nginx nginx
# Run guardrail in a privileged container sharing host PID
# Then simulate a malicious process inside the container
docker exec test-nginx touch /tmp/evil && /tmp/evil
# Assert that guardrail killed /tmp/evil

12. Performance Optimisation
Event batching: Collect multiple events in a slice before evaluating to reduce lock contention.

Map‑based whitelist: Use sync.Map for concurrent read‑heavy lookups.

eBPF maps: Pass decisions from kernel to user space via maps to avoid frequent syscalls.

Profiling: Use pprof to identify bottlenecks (CPU profile, heap profile).

13. Resilience & Recovery
Health endpoint: Provide /health for readiness probes.

Watchdog: If the guardrail process dies, systemd or Kubernetes restarts it.

State persistence: Store the seen PID set in a file so that after restart, the guardrail remembers which processes it has already evaluated.

14. Example: Rogue OpenAI Agent in Go
Assume the guardrail is deployed on the host. When the agent spawns /tmp/evil_script.py:

eBPF execve tracepoint sends event to Go daemon.

The decision engine finds no whitelist hash, blacklists /tmp/*, so it returns Kill.

The response handler calls syscall.Kill on the PID and also terminates its parent process (the agent) to prevent further attempts.

A JSON alert is sent to the SIEM.

All in < 50ms.

15. Additional Go‑Specific Considerations
Logging: Use logrus with structured fields for easy correlation.

Metrics: Export Prometheus metrics (e.g., guardrail_events_total{decision="kill"}).

Configuration reload: Handle SIGHUP to reload whitelist without restart.

eBPF compatibility: Ensure kernel version ≥ 4.15 (for tracepoint) and >= 5.8 (for cgroup hooks). Fallback to gopsutil scans if eBPF unavailable.

16. Conclusion
Building the guardrail in Go is a strategic choice that yields a high‑performance, maintainable, and deployable solution. The combination of eBPF for kernel‑level events and Go’s concurrency model provides a responsive and reliable defence against rogue agents.

All code samples above are ready to be extended into a production system. The full implementation can be packaged as a single binary with minimal external dependencies, making it ideal for both cloud and edge environments.



# Step 6: Automatic License Enforcement (Technical Check)
# Add this simple logic to your Go main.go to protect your business model:

# package main

# import (
#     "os"
#     "github.com/yourcompany/guardrail/license"
# )

# func main() {
#     // Check for enterprise license key
#     key := os.Getenv("GUARDRAIL_LICENSE_KEY")
#     valid, tier := license.Validate(key)

#     if !valid {
#         logrus.Warn("Running under AGPL-3.0 Open Source license. Commercial use restricted.")
#         // Enable only basic features
#         startOpenSourceMode()
#     } else if tier == "enterprise" {
#         logrus.Info("Enterprise license detected. Full features enabled.")
#         startEnterpriseMode()
#     }
# }

Also create test cases
