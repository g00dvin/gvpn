package main

import (
	"crypto/tls"
	"path/filepath"
	"testing"
)

func TestGenerateStandardCertIsUsable(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "std.crt")
	keyPath := filepath.Join(dir, "std.key")
	if err := generateStandardCert("vpn.example.com", certPath, keyPath, 365); err != nil {
		t.Fatalf("generateStandardCert: %v", err)
	}
	// The output must load as a usable TLS keypair.
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
}
