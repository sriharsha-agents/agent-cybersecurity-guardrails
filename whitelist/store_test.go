package whitelist

import (
	"testing"

	"agent-cybersecurity-guardrails/config"
)

func TestNewStore(t *testing.T) {
	entries := []config.WhitelistEntry{
		{Path: "/usr/bin/docker", SHA256: "abc123"},
		{Path: "/usr/bin/ssh", SHA256: ""},
	}
	store := New(entries)
	if store.Count() != 2 {
		t.Errorf("expected 2 entries, got %d", store.Count())
	}
}

func TestIsTrustedByPath(t *testing.T) {
	entries := []config.WhitelistEntry{
		{Path: "/usr/bin/ssh", SHA256: ""},
	}
	store := New(entries)

	if !store.IsTrusted("/usr/bin/ssh", "", nil) {
		t.Error("expected /usr/bin/ssh to be trusted by path")
	}
	if store.IsTrusted("/usr/bin/bad", "", nil) {
		t.Error("expected /usr/bin/bad to not be trusted")
	}
}

func TestIsTrustedByHash(t *testing.T) {
	entries := []config.WhitelistEntry{
		{Path: "/usr/bin/docker", SHA256: "abc123"},
	}
	store := New(entries)

	if !store.IsTrusted("/usr/bin/docker", "abc123", nil) {
		t.Error("expected docker with correct hash to be trusted")
	}
	if store.IsTrusted("/usr/bin/docker", "wrong_hash", nil) {
		t.Error("expected docker with wrong hash to not be trusted")
	}
}

func TestIsTrustedWithArgs(t *testing.T) {
	entries := []config.WhitelistEntry{
		{Path: "/usr/bin/curl", SHA256: "", AllowedArgs: []string{"-H", "-X", "-d"}},
	}
	store := New(entries)

	if !store.IsTrusted("/usr/bin/curl", "", []string{"-H", "-X"}) {
		t.Error("expected curl with allowed args to be trusted")
	}
	if store.IsTrusted("/usr/bin/curl", "", []string{"-H", "--bad-arg"}) {
		t.Error("expected curl with disallowed arg to not be trusted")
	}
}

func TestAddAndRemove(t *testing.T) {
	store := New(nil)
	store.Add(config.WhitelistEntry{Path: "/tmp/new", SHA256: "def456"})
	if store.Count() != 1 {
		t.Errorf("expected 1 entry after add, got %d", store.Count())
	}

	store.Remove("/tmp/new")
	if store.Count() != 0 {
		t.Errorf("expected 0 entries after remove, got %d", store.Count())
	}
}

func TestGetByPath(t *testing.T) {
	entries := []config.WhitelistEntry{
		{Path: "/usr/bin/test", SHA256: "hash1", AllowedPorts: []int{80, 443}},
	}
	store := New(entries)

	entry, ok := store.GetByPath("/usr/bin/test")
	if !ok {
		t.Fatal("expected to find entry by path")
	}
	if entry.SHA256 != "hash1" {
		t.Errorf("expected sha256 'hash1', got %q", entry.SHA256)
	}
	if len(entry.AllowedPorts) != 2 {
		t.Errorf("expected 2 allowed ports, got %d", len(entry.AllowedPorts))
	}
}

func TestGetByHash(t *testing.T) {
	entries := []config.WhitelistEntry{
		{Path: "/usr/bin/test", SHA256: "hash1"},
	}
	store := New(entries)

	entry, ok := store.GetByHash("hash1")
	if !ok {
		t.Fatal("expected to find entry by hash")
	}
	if entry.Path != "/usr/bin/test" {
		t.Errorf("expected path '/usr/bin/test', got %q", entry.Path)
	}
}

func TestEmptyStore(t *testing.T) {
	store := New(nil)
	if store.Count() != 0 {
		t.Errorf("expected 0 entries, got %d", store.Count())
	}
	if store.IsTrusted("/any/path", "", nil) {
		t.Error("expected empty store to not trust anything")
	}
}
