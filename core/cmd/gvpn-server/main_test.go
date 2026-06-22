package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gencert (standard) must produce a usable keypair via the dispatch path.
func TestGencertStandardViaDispatch(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "std.crt")
	key := filepath.Join(dir, "std.key")
	if err := dispatch([]string{"gencert", "--standard", "--cn", "vpn.example.com", "--cert", cert, "--key", key}); err != nil {
		t.Fatalf("dispatch gencert: %v", err)
	}
	for _, p := range []string{cert, key} {
		fi, err := os.Stat(p)
		if err != nil || fi.Size() == 0 {
			t.Fatalf("expected non-empty %s: %v", p, err)
		}
	}
}

func TestDispatchUnknownCommand(t *testing.T) {
	if err := dispatch([]string{"frobnicate"}); err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

func TestAdminPasswdSubcommand(t *testing.T) {
	hash, err := bcryptHash("hunter2")
	if err != nil {
		t.Fatalf("bcryptHash: %v", err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("not a bcrypt hash: %q", hash)
	}
	if err := dispatch([]string{"admin-passwd", "--password", "hunter2"}); err != nil {
		t.Fatalf("dispatch admin-passwd: %v", err)
	}
}
