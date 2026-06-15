package provision

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/wgengine"
)

// compile-time: FileStore satisfies authgate.DeviceStore.
var _ authgate.DeviceStore = (*FileStore)(nil)

func newDevice(t *testing.T) (Bundle, Device) {
	t.Helper()
	srv, _ := wgengine.GeneratePrivateKey()
	b, d, err := Generate(GenerateParams{ServerWGPublicKey: srv.PublicKey(), ServerEndpoint: "h:443", ServerName: "h"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return b, d
}

func TestLoadRegistryMissingFileIsEmpty(t *testing.T) {
	devs, err := LoadRegistry(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("LoadRegistry(missing): %v", err)
	}
	if len(devs) != 0 {
		t.Fatalf("missing registry returned %d devices, want 0", len(devs))
	}
}

func TestAppendAndLoad(t *testing.T) {
	reg := filepath.Join(t.TempDir(), "devices.json")
	_, d1 := newDevice(t)
	_, d2 := newDevice(t)
	if err := AppendDevice(reg, d1); err != nil {
		t.Fatalf("append 1: %v", err)
	}
	if err := AppendDevice(reg, d2); err != nil {
		t.Fatalf("append 2: %v", err)
	}
	devs, err := LoadRegistry(reg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(devs) != 2 {
		t.Fatalf("loaded %d devices, want 2", len(devs))
	}
}

func TestAppendRejectsDuplicate(t *testing.T) {
	reg := filepath.Join(t.TempDir(), "devices.json")
	_, d := newDevice(t)
	if err := AppendDevice(reg, d); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := AppendDevice(reg, d); err == nil {
		t.Fatal("appending a duplicate DeviceID: want error, got nil")
	}
}

func TestFileStoreLookups(t *testing.T) {
	reg := filepath.Join(t.TempDir(), "devices.json")
	b, d := newDevice(t)
	if err := AppendDevice(reg, d); err != nil {
		t.Fatalf("append: %v", err)
	}
	store, err := NewFileStore(reg)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	id, err := ParseDeviceID(d.DeviceID)
	if err != nil {
		t.Fatalf("ParseDeviceID: %v", err)
	}
	psk, ok := store.Lookup(id)
	if !ok {
		t.Fatal("Lookup: device not found")
	}
	if hex.EncodeToString(psk) != b.AuthPSK {
		t.Fatal("Lookup PSK mismatch with bundle")
	}
	wgPub, ok := store.WGPublicKey(id)
	if !ok {
		t.Fatal("WGPublicKey: device not found")
	}
	priv, _ := ParseKey(b.WGPrivateKey)
	if wgPub != priv.PublicKey() {
		t.Fatal("WGPublicKey is not the public half of the bundle's private key")
	}
	if _, ok := store.Lookup([16]byte{0xFF}); ok {
		t.Fatal("Lookup unknown device returned ok")
	}
}

func TestParseDeviceIDRoundTrip(t *testing.T) {
	id, _ := NewDeviceID()
	parsed, err := ParseDeviceID(id.String())
	if err != nil {
		t.Fatalf("ParseDeviceID: %v", err)
	}
	if !bytes.Equal(parsed[:], id[:]) {
		t.Fatal("ParseDeviceID round trip mismatch")
	}
}
