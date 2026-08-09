package whitelist

import (
	"sync"

	"agent-cybersecurity-guardrails/config"
)

// Store is a concurrent-safe whitelist store indexed by path and SHA256 hash.
type Store struct {
	mu     sync.RWMutex
	byPath map[string]config.WhitelistEntry
	byHash map[string]config.WhitelistEntry
}

// New creates a new Store and populates it from the given whitelist entries.
func New(entries []config.WhitelistEntry) *Store {
	s := &Store{
		byPath: make(map[string]config.WhitelistEntry),
		byHash: make(map[string]config.WhitelistEntry),
	}
	for _, e := range entries {
		s.add(e)
	}
	return s
}

// add inserts an entry without locking (internal use).
func (s *Store) add(e config.WhitelistEntry) {
	s.byPath[e.Path] = e
	if e.SHA256 != "" {
		s.byHash[e.SHA256] = e
	}
}

// IsTrusted checks if the given path/hash/args combination is authorized.
func (s *Store) IsTrusted(path, hash string, args []string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check by hash first (most specific)
	if hash != "" {
		if entry, ok := s.byHash[hash]; ok {
			return matchArgs(entry.AllowedArgs, args)
		}
	}

	// Check by path
	if entry, ok := s.byPath[path]; ok {
		// If entry has no hash requirement, trust by path alone
		if entry.SHA256 == "" {
			return matchArgs(entry.AllowedArgs, args)
		}
		// If entry has hash, it must match
		if entry.SHA256 == hash {
			return matchArgs(entry.AllowedArgs, args)
		}
	}

	return false
}

// Add adds a new entry to the whitelist (thread-safe).
func (s *Store) Add(e config.WhitelistEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.add(e)
}

// Remove removes an entry by path (thread-safe).
func (s *Store) Remove(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.byPath[path]; ok {
		if entry.SHA256 != "" {
			delete(s.byHash, entry.SHA256)
		}
		delete(s.byPath, path)
	}
}

// GetByPath returns the whitelist entry for a path, or false if not found.
func (s *Store) GetByPath(path string) (config.WhitelistEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.byPath[path]
	return entry, ok
}

// GetByHash returns the whitelist entry for a hash, or false if not found.
func (s *Store) GetByHash(hash string) (config.WhitelistEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.byHash[hash]
	return entry, ok
}

// Count returns the number of entries in the whitelist.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byPath)
}

// matchArgs checks if the process args are allowed by the whitelist entry's allowed_args.
// If allowedArgs is empty, all args are permitted.
func matchArgs(allowedArgs, processArgs []string) bool {
	if len(allowedArgs) == 0 {
		return true
	}
	for _, arg := range processArgs {
		found := false
		for _, allowed := range allowedArgs {
			if arg == allowed {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
