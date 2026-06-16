package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/g00dvin/gvpn/core/provision"
)

func envKey(t *testing.T) { t.Helper(); t.Setenv("GVPN_MASTER_KEY", strings.Repeat("ab", 32)) }

func TestUserAddEmitsBundleAndRegisters(t *testing.T) {
	envKey(t)
	dir := t.TempDir()
	reg := filepath.Join(dir, "registry.json")
	out := filepath.Join(dir, "alice.gvpn")
	var buf bytes.Buffer
	err := run([]string{
		"user", "add", "alice",
		"--registry", reg, "--host", "vpn.example.com:443", "--sni", "vpn.example.com",
		"--out", out,
	}, &buf)
	if err != nil {
		t.Fatalf("user add: %v", err)
	}
	if !strings.Contains(buf.String(), "gvpn://enroll?") {
		t.Fatalf("output missing deep link: %s", buf.String())
	}
	c, _ := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	fs, err := provision.NewFileStore(reg, c)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, ok := fs.User("alice"); !ok {
		t.Fatal("alice not registered")
	}
}

func TestDeviceAddAllocatesIPAndRegisters(t *testing.T) {
	envKey(t)
	dir := t.TempDir()
	reg := filepath.Join(dir, "registry.json")
	var buf bytes.Buffer
	if err := run([]string{"user", "add", "bob", "--registry", reg,
		"--host", "h:443", "--sni", "h", "--out", filepath.Join(dir, "bob.gvpn")}, &buf); err != nil {
		t.Fatalf("user add: %v", err)
	}
	buf.Reset()
	srvPriv, _ := provision.ParseKey(strings.Repeat("cd", 32))
	_ = srvPriv
	err := run([]string{"device", "add", "--user", "bob", "--registry", reg,
		"--server-wg-pubkey", strings.Repeat("cd", 32), "--endpoint", "h:443", "--server-name", "h",
		"--subnet", "10.100.0.0/24", "--out", filepath.Join(dir, "dev.json")}, &buf)
	if err != nil {
		t.Fatalf("device add: %v", err)
	}
	if !strings.Contains(buf.String(), "10.100.0.2") {
		t.Fatalf("expected allocated IP 10.100.0.2 in output: %s", buf.String())
	}
}

func TestUserAddRequiresMasterKey(t *testing.T) {
	t.Setenv("GVPN_MASTER_KEY", "")
	var buf bytes.Buffer
	err := run([]string{"user", "add", "alice", "--registry",
		filepath.Join(t.TempDir(), "r.json"), "--host", "h:443", "--sni", "h"}, &buf)
	if err == nil {
		t.Fatal("expected master-key error")
	}
}
