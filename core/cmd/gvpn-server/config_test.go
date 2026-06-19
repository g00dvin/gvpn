package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigParsesAndDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	yaml := `
server:
  listen: "0.0.0.0:443"
tls:
  cert: /etc/gvpn/gost.crt
  key: /etc/gvpn/gost.key
  ca: /etc/gvpn/ca.crt
wireguard:
  private_key: "aa"
  address: "10.100.0.1/24"
registry: /etc/gvpn/registry.json
master_key_file: /etc/gvpn/master.key
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Server.Listen != "0.0.0.0:443" {
		t.Fatalf("listen = %q", cfg.Server.Listen)
	}
	if cfg.TLS.Cert != "/etc/gvpn/gost.crt" || cfg.TLS.Key != "/etc/gvpn/gost.key" || cfg.TLS.CA != "/etc/gvpn/ca.crt" {
		t.Fatalf("tls = %+v", cfg.TLS)
	}
	if cfg.WireGuard.Address != "10.100.0.1/24" {
		t.Fatalf("address = %q", cfg.WireGuard.Address)
	}
	if cfg.Registry != "/etc/gvpn/registry.json" || cfg.MasterKeyFile != "/etc/gvpn/master.key" {
		t.Fatalf("registry/master = %q/%q", cfg.Registry, cfg.MasterKeyFile)
	}
	if cfg.Subnet() != "10.100.0.0/24" {
		t.Fatalf("Subnet() = %q, want 10.100.0.0/24", cfg.Subnet())
	}
}

func TestLoadConfigRejectsMissingRequired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte("server:\n  listen: \":443\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected validation error for missing required fields")
	}
}

func TestLoadConfigRejectsBadAddress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	yaml := "server:\n  listen: \":443\"\ntls:\n  cert: c\n  key: k\nwireguard:\n  private_key: aa\n  address: not-a-cidr\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error for malformed wireguard.address")
	}
}
