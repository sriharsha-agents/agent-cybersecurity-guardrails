package monitor

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"agent-cybersecurity-guardrails/config"
)

// NetworkConnection represents an outbound network connection.
type NetworkConnection struct {
	PID        int       `json:"pid"`
	LocalAddr  string    `json:"local_addr"`
	RemoteAddr string    `json:"remote_addr"`
	RemoteIP   string    `json:"remote_ip"`
	RemotePort int       `json:"remote_port"`
	Protocol   string    `json:"protocol"`
	Status     string    `json:"status"`
	Timestamp  time.Time `json:"timestamp"`
}

// NetworkEvent is emitted when a suspicious network connection is detected.
type NetworkEvent struct {
	Connection NetworkConnection `json:"connection"`
	Reason     string            `json:"reason"`
	Timestamp  time.Time         `json:"timestamp"`
}

// NetworkMonitor monitors outbound network connections for policy violations.
type NetworkMonitor struct {
	cfg       *config.NetworkConfig
	eventChan chan<- NetworkEvent
	connTrack map[string]int64 // IP -> last connection timestamp
	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	ticker    *time.Ticker
}

// NewNetworkMonitor creates a new NetworkMonitor.
func NewNetworkMonitor(cfg *config.NetworkConfig, eventChan chan<- NetworkEvent) *NetworkMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &NetworkMonitor{
		cfg:       cfg,
		eventChan: eventChan,
		connTrack: make(map[string]int64),
		ctx:       ctx,
		cancel:    cancel,
		ticker:    time.NewTicker(2 * time.Second),
	}
}

// Start begins the network monitoring loop.
func (nm *NetworkMonitor) Start() {
	go nm.run()
}

// Stop stops the network monitoring loop.
func (nm *NetworkMonitor) Stop() {
	nm.cancel()
	nm.ticker.Stop()
}

func (nm *NetworkMonitor) run() {
	for {
		select {
		case <-nm.ctx.Done():
			return
		case <-nm.ticker.C:
			nm.checkConnections()
		}
	}
}

// checkConnections enumerates current TCP connections and checks policies.
func (nm *NetworkMonitor) checkConnections() {
	conns, err := nm.getTCPConnections()
	if err != nil {
		log.Printf("[network_monitor] get connections error: %v", err)
		return
	}

	now := time.Now().Unix()

	for _, conn := range conns {
		reason := nm.evaluateConnection(conn, now)
		if reason != "" {
			evt := NetworkEvent{
				Connection: conn,
				Reason:     reason,
				Timestamp:  time.Now(),
			}
			select {
			case nm.eventChan <- evt:
			default:
				log.Printf("[network_monitor] event channel full, dropping event for PID %d", conn.PID)
			}
		}
	}

	// Clean old entries
	nm.mu.Lock()
	for ip, ts := range nm.connTrack {
		if now-ts > 120 {
			delete(nm.connTrack, ip)
		}
	}
	nm.mu.Unlock()
}

// evaluateConnection checks a connection against network policies. Returns reason string if violation.
func (nm *NetworkMonitor) evaluateConnection(conn NetworkConnection, now int64) string {
	// Check blocklist IPs
	for _, blockedIP := range nm.cfg.BlocklistIPs {
		if conn.RemoteIP == blockedIP {
			return fmt.Sprintf("connection to blocklisted IP %s", blockedIP)
		}
	}

	// Track connection rate per IP
	nm.mu.Lock()
	nm.connTrack[conn.RemoteIP] = now
	count := 0
	for _, ts := range nm.connTrack {
		if now-ts < 60 {
			count++
		}
	}
	nm.mu.Unlock()

	if count > nm.cfg.MaxConnections && nm.cfg.MaxConnections > 0 {
		return fmt.Sprintf("connection rate limit exceeded (%d > %d)", count, nm.cfg.MaxConnections)
	}

	return ""
}

// getTCPConnections reads /proc/net/tcp to get active connections.
func (nm *NetworkMonitor) getTCPConnections() ([]NetworkConnection, error) {
	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		// Fallback: try netlink
		return nm.getTCPConnectionsFallback()
	}

	var conns []NetworkConnection
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // skip header
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		conn, err := parseTCPLine(line)
		if err != nil {
			continue
		}
		conns = append(conns, conn)
	}

	return conns, nil
}

// parseTCPLine parses a single line from /proc/net/tcp.
func parseTCPLine(line string) (NetworkConnection, error) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return NetworkConnection{}, fmt.Errorf("not enough fields")
	}

	// Local address and port (hex)
	localParts := strings.Split(fields[1], ":")
	if len(localParts) != 2 {
		return NetworkConnection{}, fmt.Errorf("invalid local addr")
	}

	// Remote address and port (hex)
	remoteParts := strings.Split(fields[2], ":")
	if len(remoteParts) != 2 {
		return NetworkConnection{}, fmt.Errorf("invalid remote addr")
	}

	remoteIP := hexToIP(remoteParts[1])
	var remotePort int
	fmt.Sscanf(remoteParts[1], "%x", &remotePort)

	// Status
	var status string
	switch fields[3] {
	case "01":
		status = "ESTABLISHED"
	case "0A":
		status = "LISTEN"
	default:
		status = fields[3]
	}

	// UID field (index 7) maps to PID approximation
	var pid int
	if len(fields) > 7 {
		fmt.Sscanf(fields[7], "%d", &pid)
	}

	return NetworkConnection{
		PID:        pid,
		LocalAddr:  localParts[0],
		RemoteAddr: remoteParts[0],
		RemoteIP:   remoteIP,
		RemotePort: remotePort,
		Protocol:   "tcp",
		Status:     status,
		Timestamp:  time.Now(),
	}, nil
}

// hexToIP converts a hex IP string from /proc/net/tcp to dotted notation.
// func hexToIP(hex string) string {
// 	var b [4]byte
// 	for i := 0; i < 4; i++ {
// 		fmt.Sscanf(hex[i*2:i*2+2], "%02x", &b[i])
// 	}
// 	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
// }

func hexToIP(hex string) string {
	if len(hex) != 8 {
		return "" // or could return hex? but caller expects IP string
	}
	var b [4]byte
	for i := 0; i < 4; i++ {
		_, err := fmt.Sscanf(hex[i*2:i*2+2], "%02x", &b[i])
		if err != nil {
			return ""
		}
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// getTCPConnectionsFallback uses net interfaces as a fallback.
func (nm *NetworkMonitor) getTCPConnectionsFallback() ([]NetworkConnection, error) {
	conns, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []NetworkConnection
	for _, iface := range conns {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.IsGlobalUnicast() {
				result = append(result, NetworkConnection{
					LocalAddr: ipnet.IP.String(),
					Protocol:  "tcp",
					Status:    "UP",
					Timestamp: time.Now(),
				})
			}
		}
	}
	return result, nil
}

// IsDomainAllowed checks if a domain matches the allowed domain patterns.
func (nm *NetworkMonitor) IsDomainAllowed(domain string) bool {
	for _, pattern := range nm.cfg.AllowedDomains {
		if wildcardMatch(pattern, domain) {
			return true
		}
	}
	return false
}

// wildcardMatch checks if a domain matches a wildcard pattern like "*.internal.com".
func wildcardMatch(pattern, domain string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == domain
	}
	// Convert wildcard to regex
	rePattern := "^" + regexp.QuoteMeta(pattern) + "$"
	rePattern = strings.ReplaceAll(rePattern, `\*`, `.*`)
	matched, _ := regexp.MatchString(rePattern, domain)
	return matched
}
