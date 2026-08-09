package engine

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"agent-cybersecurity-guardrails/config"
	"agent-cybersecurity-guardrails/detector"
	"agent-cybersecurity-guardrails/monitor"
	"agent-cybersecurity-guardrails/whitelist"
)

// Decision represents the outcome of the decision engine.
type Decision int

const (
	Allow Decision = iota
	Kill
	Quarantine
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "ALLOW"
	case Kill:
		return "KILL"
	case Quarantine:
		return "QUARANTINE"
	default:
		return "UNKNOWN"
	}
}

// Verdict contains the decision and the reason.
type Verdict struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
}

// Engine evaluates processes against whitelist, blacklist, and behavioral policies.
type Engine struct {
	whitelist   *whitelist.Store
	blacklist   *config.BlacklistConfig
	networkCfg  *config.NetworkConfig
	behaviour   *config.BehaviourConfig
	responseCfg *config.ResponseConfig
	anomalyDet  *detector.AnomalyDetector
	blacklistRE []*regexp.Regexp
}

// New creates a new decision Engine.
func New(cfg *config.Config, wl *whitelist.Store, ad *detector.AnomalyDetector) *Engine {
	// Compile blacklist patterns
	var reList []*regexp.Regexp
	for _, pattern := range cfg.Blacklist.Executables {
		re, err := wildcardToRegex(pattern)
		if err == nil {
			reList = append(reList, re)
		}
	}

	return &Engine{
		whitelist:   wl,
		blacklist:   &cfg.Blacklist,
		networkCfg:  &cfg.Network,
		behaviour:   &cfg.Behaviour,
		responseCfg: &cfg.Response,
		anomalyDet:  ad,
		blacklistRE: reList,
	}
}

// EvaluateProcess evaluates a process event and returns a verdict.
func (e *Engine) EvaluateProcess(evt monitor.ProcessEvent) Verdict {
	info := evt.Info

	// 1. Check whitelist
	if e.whitelist.IsTrusted(info.Exe, "", info.CmdlineArr) {
		return Verdict{Decision: Allow, Reason: "whitelisted"}
	}

	// 2. Check blacklist executables
	for _, re := range e.blacklistRE {
		if re.MatchString(info.Exe) {
			return Verdict{Decision: Kill, Reason: fmt.Sprintf("blacklisted executable: %s matches %s", info.Exe, re.String())}
		}
	}

	// 3. Check blacklist arguments
	for _, arg := range info.CmdlineArr {
		for _, blockedArg := range e.blacklist.Args {
			if strings.Contains(arg, blockedArg) {
				return Verdict{Decision: Kill, Reason: fmt.Sprintf("blacklisted argument: %s", blockedArg)}
			}
		}
	}

	// 4. Check behavioral anomalies
	if anomaly := e.anomalyDet.CheckProcess(info); anomaly != "" {
		return Verdict{Decision: Kill, Reason: fmt.Sprintf("behavioral anomaly: %s", anomaly)}
	}

	// 5. Unknown process - allow by default to avoid killing legitimate software
	return Verdict{Decision: Allow, Reason: fmt.Sprintf("unknown process: %s", info.Exe)}
}

// EvaluateNetwork evaluates a network event and returns a verdict.
func (e *Engine) EvaluateNetwork(evt monitor.NetworkEvent) Verdict {
	if evt.Reason != "" {
		return Verdict{Decision: Kill, Reason: fmt.Sprintf("network violation: %s", evt.Reason)}
	}
	return Verdict{Decision: Allow, Reason: "network ok"}
}

// wildcardToRegex converts a glob pattern like "/tmp/*" to a compiled regex.
func wildcardToRegex(pattern string) (*regexp.Regexp, error) {
	// Handle path-based patterns
	rePattern := "^" + regexp.QuoteMeta(pattern) + "$"
	rePattern = strings.ReplaceAll(rePattern, `\*`, `.*`)
	rePattern = strings.ReplaceAll(rePattern, `\?`, `.`)
	return regexp.Compile(rePattern)
}

// IsBlacklistedPath checks if a path matches any blacklist pattern.
func (e *Engine) IsBlacklistedPath(path string) bool {
	for _, re := range e.blacklistRE {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// GetAllowedPorts returns the allowed ports for a whitelisted entry.
func (e *Engine) GetAllowedPorts(path string) []int {
	entry, ok := e.whitelist.GetByPath(path)
	if !ok {
		return nil
	}
	return entry.AllowedPorts
}

// CheckArgBlacklist checks if any arg matches the blacklist.
func (e *Engine) CheckArgBlacklist(args []string) (bool, string) {
	for _, arg := range args {
		for _, blocked := range e.blacklist.Args {
			if strings.Contains(arg, blocked) {
				return true, blocked
			}
		}
	}
	return false, ""
}

// GetProcessName extracts the basename from an exe path.
func GetProcessName(exe string) string {
	return filepath.Base(exe)
}
