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

func TestMapStoreEnrollLookup(t *testing.T) {
	uid := [16]byte{7, 7, 7}
	store := NewMapStoreWithEnroll(nil, map[[16]byte][]byte{uid: []byte("enroll")})
	psk, ok := store.EnrollLookup(uid)
	if !ok || !bytes.Equal(psk, []byte("enroll")) {
		t.Fatalf("EnrollLookup = %q,%v want enroll,true", psk, ok)
	}
	if _, ok := store.EnrollLookup([16]byte{8}); ok {
		t.Fatal("EnrollLookup unknown user: ok = true")
	}
	// A plain NewMapStore has no enrollment users.
	if _, ok := NewMapStore(nil).EnrollLookup(uid); ok {
		t.Fatal("NewMapStore should have no enroll users")
	}
}
