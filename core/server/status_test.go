package server

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/session"
	"github.com/g00dvin/gvpn/core/wgengine"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// newStatusServer builds a server with one provisioned device and returns the
// server, its store, and the device's 16-byte id.
func newStatusServer(t *testing.T) (*Server, *provision.FileStore, [16]byte) {
	t.Helper()
	reg := filepath.Join(t.TempDir(), "registry.json")
	c, _ := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	store, err := provision.NewFileStore(reg, c)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if _, _, err := store.AddUser("u"); err != nil {
		t.Fatal(err)
	}
	devPriv, _ := wgengine.GeneratePrivateKey()
	dev := provision.Device{DeviceID: "22222222-2222-4222-8222-222222222222",
		User: "u", WGPublic: devPriv.PublicKey().Hex(), TunnelIP: "10.100.0.2", Source: "admin"}
	if err := store.AddDevice(dev, []byte("psk")); err != nil {
		t.Fatal(err)
	}
	srvWG, _ := wgengine.GeneratePrivateKey()
	tunDev, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.100.0.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(authgate.NewGate(store, nil), session.NewManager(time.Minute), store,
		Config{WGPrivateKey: srvWG}, tunDev)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := provision.ParseDeviceID(dev.DeviceID)
	return srv, store, id
}

func TestServerActiveDevicesEmpty(t *testing.T) {
	srv, _, _ := newStatusServer(t)
	defer srv.Close()
	if got := srv.ActiveDevices(); len(got) != 0 {
		t.Fatalf("ActiveDevices on idle server = %v, want empty", got)
	}
}

func TestServerRevokeDeviceRemovesRecord(t *testing.T) {
	srv, store, id := newStatusServer(t)
	defer srv.Close()
	if _, ok := store.Device(id); !ok {
		t.Fatal("device should exist before revoke")
	}
	if err := srv.RevokeDevice(id); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if _, ok := store.Device(id); ok {
		t.Fatal("device record still present after RevokeDevice")
	}
	// Revoking an unknown device is a no-op.
	if err := srv.RevokeDevice([16]byte{0xFF}); err != nil {
		t.Fatalf("RevokeDevice(unknown) = %v, want nil", err)
	}
}
