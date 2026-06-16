package provision

import (
	"os"
	"strings"
	"testing"
)

func testKeyHex() string { return strings.Repeat("ab", 32) } // 32 bytes

func TestCipherSealOpenRoundTrip(t *testing.T) {
	c, err := NewCipherFromHex(testKeyHex())
	if err != nil {
		t.Fatalf("NewCipherFromHex: %v", err)
	}
	plain := []byte("super-secret-psk")
	enc, err := c.Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if strings.Contains(enc, "super-secret") {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := c.Open(enc)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("round trip = %q, want %q", got, plain)
	}
}

func TestCipherSealIsNondeterministic(t *testing.T) {
	c, _ := NewCipherFromHex(testKeyHex())
	a, _ := c.Seal([]byte("x"))
	b, _ := c.Seal([]byte("x"))
	if a == b {
		t.Fatal("Seal must use a fresh nonce each call")
	}
}

func TestCipherOpenRejectsTamper(t *testing.T) {
	c, _ := NewCipherFromHex(testKeyHex())
	enc, _ := c.Seal([]byte("hello"))
	if _, err := c.Open(enc + "AA"); err == nil {
		t.Fatal("Open accepted tampered ciphertext")
	}
}

func TestLoadMasterKeyFromEnv(t *testing.T) {
	t.Setenv("GVPN_MASTER_KEY", testKeyHex())
	key, err := LoadMasterKey("")
	if err != nil {
		t.Fatalf("LoadMasterKey env: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key len = %d, want 32", len(key))
	}
}

func TestLoadMasterKeyFromFile(t *testing.T) {
	t.Setenv("GVPN_MASTER_KEY", "")
	p := t.TempDir() + "/master.key"
	if err := os.WriteFile(p, []byte(testKeyHex()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := LoadMasterKey(p)
	if err != nil {
		t.Fatalf("LoadMasterKey file: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key len = %d, want 32", len(key))
	}
}

func TestLoadMasterKeyMissing(t *testing.T) {
	t.Setenv("GVPN_MASTER_KEY", "")
	if _, err := LoadMasterKey(""); err == nil {
		t.Fatal("expected error when no key source is given")
	}
}
