package provision

import (
	"path/filepath"
	"strings"
	"testing"
)

func newTestStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.json")
	c, err := NewCipherFromHex(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	fs, err := NewFileStore(path, c)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return fs, path
}

func TestFileStoreAddUserAndDevice(t *testing.T) {
	fs, path := newTestStore(t)
	u, _, err := fs.AddUser("alice")
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if u.DeviceCap != 5 || !u.EnrollOpen {
		t.Fatalf("defaults: cap=%d open=%v", u.DeviceCap, u.EnrollOpen)
	}
	wg, _ := GeneratePrivateKeyHex(t)
	dev := Device{DeviceID: "22222222-2222-4222-8222-222222222222", User: "alice",
		WGPublic: wg, TunnelIP: "10.100.0.2", Source: "admin"}
	psk := []byte("device-psk-bytes")
	if err := fs.AddDevice(dev, psk); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}

	// Lookup decrypts the per-device PSK (authgate.DeviceStore behavior).
	id, _ := ParseDeviceID(dev.DeviceID)
	got, ok := fs.Lookup(id)
	if !ok || string(got) != string(psk) {
		t.Fatalf("Lookup = %q,%v want %q", got, ok, psk)
	}
	if _, ok := fs.WGPublicKey(id); !ok {
		t.Fatal("WGPublicKey missing")
	}
	rec, ok := fs.Device(id)
	if !ok || rec.TunnelIP != "10.100.0.2" {
		t.Fatalf("Device = %+v,%v", rec, ok)
	}

	// Persisted across reload.
	c, _ := NewCipherFromHex(strings.Repeat("ab", 32))
	fs2, err := NewFileStore(path, c)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got2, ok := fs2.Lookup(id); !ok || string(got2) != string(psk) {
		t.Fatalf("reloaded Lookup = %q,%v", got2, ok)
	}
}

func TestFileStoreEnrollPSKAndCap(t *testing.T) {
	fs, _ := newTestStore(t)
	u, enrollPSK, err := fs.AddUser("bob")
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	uid, _ := ParseDeviceID(u.ID)
	got, ok := fs.EnrollPSK(uid)
	if !ok || string(got) != string(enrollPSK) {
		t.Fatalf("EnrollPSK = %q,%v want the minted secret", got, ok)
	}
	if n := fs.DeviceCount("bob"); n != 0 {
		t.Fatalf("device count = %d, want 0", n)
	}
}

func TestFileStoreRemoveDevice(t *testing.T) {
	fs, _ := newTestStore(t)
	if _, _, err := fs.AddUser("alice"); err != nil {
		t.Fatal(err)
	}
	wg, _ := GeneratePrivateKeyHex(t)
	dev := Device{DeviceID: "22222222-2222-4222-8222-222222222222", User: "alice",
		WGPublic: wg, TunnelIP: "10.100.0.2", Source: "admin"}
	if err := fs.AddDevice(dev, []byte("psk")); err != nil {
		t.Fatal(err)
	}
	if err := fs.RemoveDevice(dev.DeviceID); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}
	id, _ := ParseDeviceID(dev.DeviceID)
	if _, ok := fs.Lookup(id); ok {
		t.Fatal("device still present after removal")
	}
}

func TestFileStoreDuplicateUser(t *testing.T) {
	fs, _ := newTestStore(t)
	if _, _, err := fs.AddUser("alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fs.AddUser("alice"); err == nil {
		t.Fatal("expected duplicate user error")
	}
}

// GeneratePrivateKeyHex returns a fresh WG public key hex for tests.
func GeneratePrivateKeyHex(t *testing.T) (string, string) {
	t.Helper()
	k, err := genWGKeyHexForTest()
	if err != nil {
		t.Fatalf("wg key: %v", err)
	}
	return k, k
}
