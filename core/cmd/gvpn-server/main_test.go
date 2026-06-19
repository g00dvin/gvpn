package main

import (
	"os"
	"path/filepath"
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
