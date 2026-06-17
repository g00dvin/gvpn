package provision

import (
	"strings"
	"testing"

	"github.com/g00dvin/gvpn/core/wgengine"
)

func TestGenerateProducesMatchingBundleAndMaterial(t *testing.T) {
	srvPriv, _ := wgengine.GeneratePrivateKey()
	b, m, err := Generate("alice", "10.100.0.2", GenerateParams{
		ServerWGPublicKey: srvPriv.PublicKey(),
		ServerEndpoint:    "vpn.example.com:443",
		ServerName:        "vpn.example.com",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if b.DeviceID != m.DeviceID || b.TunnelIP != "10.100.0.2" || m.User != "alice" {
		t.Fatalf("bundle/material mismatch: %+v / %+v", b, m)
	}
	// The bundle's private key must match the material's public key.
	priv, err := ParseKey(b.WGPrivateKey)
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	if priv.PublicKey().Hex() != m.WGPublic {
		t.Fatal("bundle private key does not match material public key")
	}
	if len(m.AuthPSK) != authPSKSize {
		t.Fatalf("auth psk len = %d", len(m.AuthPSK))
	}
}

func TestMaterialRecordEncryptsPSK(t *testing.T) {
	c, _ := NewCipherFromHex(strings.Repeat("ab", 32))
	_, m, _ := Generate("alice", "10.100.0.2", GenerateParams{ServerEndpoint: "h:443", ServerName: "h"})
	rec, err := m.Record(c, "admin")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if rec.AuthPSKEnc == "" || strings.Contains(rec.AuthPSKEnc, string(m.AuthPSK)) {
		t.Fatal("record PSK not encrypted")
	}
	got, err := c.Open(rec.AuthPSKEnc)
	if err != nil || string(got) != string(m.AuthPSK) {
		t.Fatalf("decrypt mismatch: %v", err)
	}
	if rec.Source != "admin" || rec.User != "alice" || rec.TunnelIP != "10.100.0.2" {
		t.Fatalf("record fields: %+v", rec)
	}
}
