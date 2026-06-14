package authgate

import (
	"bytes"
	"testing"
)

func TestMapStoreLookup(t *testing.T) {
	dev := [16]byte{1, 2, 3}
	store := NewMapStore(map[[16]byte][]byte{dev: []byte("psk")})

	psk, ok := store.Lookup(dev)
	if !ok {
		t.Fatal("Lookup registered device: ok = false")
	}
	if !bytes.Equal(psk, []byte("psk")) {
		t.Fatalf("psk = %q, want %q", psk, "psk")
	}
	if _, ok := store.Lookup([16]byte{9}); ok {
		t.Fatal("Lookup unknown device: ok = true")
	}
}

func TestMapStoreNil(t *testing.T) {
	store := NewMapStore(nil)
	if _, ok := store.Lookup([16]byte{1}); ok {
		t.Fatal("Lookup on empty store: ok = true")
	}
}
