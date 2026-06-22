package main

import (
	"testing"
	"time"
)

func TestShareTokenMintResolveRevoke(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	st := newShareTokenStore(time.Hour)
	st.now = func() time.Time { return now }

	tok, err := st.Mint("alice")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if len(tok) < 20 {
		t.Fatalf("token too short: %q", tok)
	}
	if h, ok := st.Resolve(tok); !ok || h != "alice" {
		t.Fatalf("Resolve = %q,%v want alice,true", h, ok)
	}
	st.Revoke(tok)
	if _, ok := st.Resolve(tok); ok {
		t.Fatal("Resolve after Revoke: ok = true")
	}
}

func TestShareTokenExpiry(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	st := newShareTokenStore(time.Hour)
	st.now = func() time.Time { return now }
	tok, _ := st.Mint("bob")
	now = now.Add(2 * time.Hour) // past TTL
	if _, ok := st.Resolve(tok); ok {
		t.Fatal("expired token resolved")
	}
}

func TestShareTokenUnknown(t *testing.T) {
	st := newShareTokenStore(time.Hour)
	if _, ok := st.Resolve("nope"); ok {
		t.Fatal("unknown token resolved")
	}
}
