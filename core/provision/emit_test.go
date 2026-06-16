package provision

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteQRPNG(t *testing.T) {
	p := filepath.Join(t.TempDir(), "code.png")
	if err := WriteQRPNG("gvpn://enroll?u=alice", p, 256); err != nil {
		t.Fatalf("WriteQRPNG: %v", err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read png: %v", err)
	}
	if len(data) < 8 || string(data[1:4]) != "PNG" {
		t.Fatal("output is not a PNG")
	}
}

func TestTerminalQR(t *testing.T) {
	s, err := TerminalQR("gvpn://enroll?u=alice")
	if err != nil {
		t.Fatalf("TerminalQR: %v", err)
	}
	if !strings.Contains(s, "\n") || len(s) < 10 {
		t.Fatal("terminal QR looks empty")
	}
}

func TestWriteQRPNGIs0600(t *testing.T) {
	p := filepath.Join(t.TempDir(), "code.png")
	if err := WriteQRPNG("gvpn://enroll?u=alice&psk=secret", p, 256); err != nil {
		t.Fatalf("WriteQRPNG: %v", err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("QR PNG mode = %v, want 0600", fi.Mode().Perm())
	}
}
