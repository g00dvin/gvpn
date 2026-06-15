package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/wgengine"
)

func TestRunProvisionsBundleAndRegistry(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "devices.json")
	out := filepath.Join(dir, "bundle.json")
	srv, _ := wgengine.GeneratePrivateKey()

	var buf bytes.Buffer
	err := run([]string{
		"--server-wg-pubkey", srv.PublicKey().Hex(),
		"--endpoint", "vpn.example.com:443",
		"--server-name", "vpn.example.com",
		"--registry", reg,
		"--out", out,
	}, &buf)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	b, err := provision.ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if b.ServerEndpoint != "vpn.example.com:443" || b.ServerName != "vpn.example.com" {
		t.Fatalf("bundle server coords wrong: %+v", b)
	}

	store, err := provision.NewFileStore(reg)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	id, _ := provision.ParseDeviceID(b.DeviceID)
	psk, ok := store.Lookup(id)
	if !ok || hex.EncodeToString(psk) != b.AuthPSK {
		t.Fatal("registry PSK does not match bundle")
	}
	priv, _ := provision.ParseKey(b.WGPrivateKey)
	if wgPub, ok := store.WGPublicKey(id); !ok || wgPub != priv.PublicKey() {
		t.Fatal("registry WG pubkey does not match bundle private key")
	}

	o := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte(b.DeviceID)) {
		t.Fatal("output should mention the DeviceID")
	}
	if bytes.Contains(buf.Bytes(), []byte(b.AuthPSK)) || bytes.Contains(buf.Bytes(), []byte(b.WGPrivateKey)) {
		t.Fatalf("output leaked secret material: %q", o)
	}
}

func TestRunRequiresServerFlags(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"--endpoint", "h:443"}, &buf); err == nil {
		t.Fatal("run without --server-wg-pubkey/--server-name: want error, got nil")
	}
}

func TestRunSecondProvisionAppends(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "devices.json")
	srv, _ := wgengine.GeneratePrivateKey()
	args := func(out string) []string {
		return []string{
			"--server-wg-pubkey", srv.PublicKey().Hex(),
			"--endpoint", "h:443", "--server-name", "h",
			"--registry", reg, "--out", out,
		}
	}
	var buf bytes.Buffer
	if err := run(args(filepath.Join(dir, "a.json")), &buf); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if err := run(args(filepath.Join(dir, "b.json")), &buf); err != nil {
		t.Fatalf("run 2: %v", err)
	}
	devs, _ := provision.LoadRegistry(reg)
	if len(devs) != 2 {
		t.Fatalf("registry has %d devices after two provisions, want 2", len(devs))
	}
}
