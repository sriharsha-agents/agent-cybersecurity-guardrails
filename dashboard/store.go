package dashboard

import (
	"agent-cybersecurity-guardrails/monitor"
	"sync"
	"time"
)

type Record struct {
	Timestamp time.Time `json:"timestamp"`
	PID       int       `json:"pid"`
	Exe       string    `json:"exe"`
	Cmd       string    `json:"cmdline"`
	Reason    string    `json:"reason"`
	Action    string    `json:"action"`
	Type      string    `json:"type"`
}

type Stats struct {
	Total int `json:"total"`
	OK    int `json:"allowed"`
	Kill  int `json:"killed"`
	Quar  int `json:"quarantined"`
	Proc  int `json:"processEvents"`
	Net   int `json:"networkEvents"`
}

type Store struct {
	mu sync.Mutex
	ev []Record
	st Stats
}

func NewStore() *Store {
	return &Store{ev: make([]Record, 0, 500)}
}

func (s *Store) Add(evt monitor.ProcessEvent, reason, action string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Total++
	s.st.Proc++
	switch action {
	case "kill":
		s.st.Kill++
	case "quarantine":
		s.st.Quar++
	default:
		s.st.OK++
	}
	if len(s.ev) < 500 {
		s.ev = append(s.ev, Record{
			Timestamp: time.Now(),
			PID:       evt.Info.PID,
			Exe:       evt.Info.Exe,
			Cmd:       evt.Info.Cmdline,
			Reason:    reason,
			Action:    action,
			Type:      "process",
		})
	}
}

func (s *Store) AddNet(evt monitor.NetworkEvent, reason, action string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Total++
	s.st.Net++
	switch action {
	case "kill":
		s.st.Kill++
	case "quarantine":
		s.st.Quar++
	default:
		s.st.OK++
	}
	if len(s.ev) < 500 {
		s.ev = append(s.ev, Record{
			Timestamp: time.Now(),
			PID:       evt.Connection.PID,
			Exe:       evt.Connection.RemoteAddr,
			Cmd:       evt.Connection.RemoteIP,
			Reason:    reason,
			Action:    action,
			Type:      "network",
		})
	}
}

func (s *Store) GetStats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

func (s *Store) GetEvents() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, len(s.ev))
	copy(out, s.ev)
	return out
}
