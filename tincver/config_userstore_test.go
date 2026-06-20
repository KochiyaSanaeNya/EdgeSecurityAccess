package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.conf")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

func TestLoadESAConfigValidatesRequiredFields(t *testing.T) {
	path := writeTempFile(t, `$servip = 172.16.16.1/24
$subnet = 172.16.16.0/24
$endpoint = example.org:30000
$tincport = 30000
$httport = 127.0.0.1:30001
$tincnet = esa
$tincdir = /etc/tinc/esa
$servname = esa_server
$servpub = `+testTincPublicKey()+`
`)

	cfg, err := loadESAConfig(path)
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	if cfg.TincPort != 30000 || cfg.IPPort != "127.0.0.1:30001" || cfg.TincNet != "esa" {
		t.Fatalf("unexpected parsed config: %+v", cfg)
	}
}

func TestLoadESAConfigRejectsInvalidPort(t *testing.T) {
	path := writeTempFile(t, `$servip = 172.16.16.1/24
$subnet = 172.16.16.0/24
$endpoint = example.org:30000
$tincport = 70000
$httport = 127.0.0.1:30001
$tincnet = esa
$tincdir = /etc/tinc/esa
$servname = esa_server
$servpub = `+testTincPublicKey()+`
`)

	if _, err := loadESAConfig(path); err == nil {
		t.Fatal("expected invalid tincport to be rejected")
	}
}

func TestLoadUserStoreRejectsDuplicateUsers(t *testing.T) {
	path := writeTempFile(t, "1:alice:10.0.0.2/32\n2:alice:10.0.0.3/32\n")

	if _, err := LoadUserStore(path); err == nil {
		t.Fatal("expected duplicate username to be rejected")
	}
}

func TestLoadUserStoreRejectsInvalidAllowedIP(t *testing.T) {
	path := writeTempFile(t, "1:alice:10.0.0.0/8\n")

	if _, err := LoadUserStore(path); err == nil {
		t.Fatal("expected overly broad allowed IP to be rejected")
	}
}

func TestLoadUserStoreRejectsDuplicateIDs(t *testing.T) {
	path := writeTempFile(t, "1:alice:10.0.0.2/32\n1:bob:10.0.0.3/32\n")

	if _, err := LoadUserStore(path); err == nil {
		t.Fatal("expected duplicate user id to be rejected")
	}
}

func TestLoadUserStoreRejectsDuplicatePeerIPs(t *testing.T) {
	path := writeTempFile(t, "1:alice:10.0.0.2\n2:bob:10.0.0.2/32\n")

	if _, err := LoadUserStore(path); err == nil {
		t.Fatal("expected duplicate peer IP to be rejected")
	}
}

func TestNewRejectsMalformedUsersDB(t *testing.T) {
	path := writeTempFile(t, "alice-without-hash\n")

	if _, err := New(path); err == nil {
		t.Fatal("expected malformed users db line to be rejected")
	}
}

func TestNewRejectsInvalidPasswordHash(t *testing.T) {
	path := writeTempFile(t, "alice:not-a-hash\n")

	if _, err := New(path); err == nil {
		t.Fatal("expected malformed password hash to be rejected")
	}
}
