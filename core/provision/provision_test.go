package provision

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/g00dvin/gvpn/core/wgengine"
)

func TestNewDeviceIDIsUUIDv4(t *testing.T) {
	id, err := NewDeviceID()
	if err != nil {
		t.Fatalf("NewDeviceID: %v", err)
	}
	if id == (DeviceID{}) {
		t.Fatal("DeviceID is all-zero")
	}
	if id[6]>>4 != 0x4 {
		t.Fatalf("version nibble = %x, want 4", id[6]>>4)
	}
	if id[8]>>6 != 0x2 {
		t.Fatalf("variant bits = %b, want 10", id[8]>>6)
	}
	s := id.String()
	if len(s) != 36 || strings.Count(s, "-") != 4 {
		t.Fatalf("String() = %q, want canonical 8-4-4-4-12 UUID", s)
	}
}

func TestGenerateProducesMatchingBundleAndDevice(t *testing.T) {
	srvPriv, _ := wgengine.GeneratePrivateKey()
	bundle, device, err := Generate(GenerateParams{
		ServerWGPublicKey: srvPriv.PublicKey(),
		ServerEndpoint:    "vpn.example.com:443",
		ServerName:        "vpn.example.com",
		ServerCAPEM:       "-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----\n",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if bundle.DeviceID != device.DeviceID {
		t.Fatal("bundle/device DeviceID mismatch")
	}
	if bundle.AuthPSK != device.AuthPSK {
		t.Fatal("bundle/device AuthPSK mismatch")
	}
	psk, err := hex.DecodeString(bundle.AuthPSK)
	if err != nil || len(psk) != 32 {
		t.Fatalf("AuthPSK hex = %q (decoded %d bytes), want 32", bundle.AuthPSK, len(psk))
	}
	priv, err := ParseKey(bundle.WGPrivateKey)
	if err != nil {
		t.Fatalf("ParseKey(WGPrivateKey): %v", err)
	}
	if priv.PublicKey().Hex() != device.WGPublicKey {
		t.Fatal("device WGPublicKey is not the public half of the bundle's private key")
	}
	if bundle.ServerWGPublicKey != srvPriv.PublicKey().Hex() {
		t.Fatal("bundle ServerWGPublicKey mismatch")
	}
	if bundle.ServerEndpoint != "vpn.example.com:443" {
		t.Fatal("ServerEndpoint not carried")
	}
}

func TestBundleJSONRoundTrip(t *testing.T) {
	srvPriv, _ := wgengine.GeneratePrivateKey()
	bundle, _, _ := Generate(GenerateParams{
		ServerWGPublicKey: srvPriv.PublicKey(),
		ServerEndpoint:    "host:443",
		ServerName:        "host",
	})
	data, err := bundle.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if got != bundle {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, bundle)
	}
}

func TestGenerateUniqueDevices(t *testing.T) {
	srvPriv, _ := wgengine.GeneratePrivateKey()
	p := GenerateParams{ServerWGPublicKey: srvPriv.PublicKey(), ServerEndpoint: "h:443", ServerName: "h"}
	a, _, _ := Generate(p)
	b, _, _ := Generate(p)
	if a.DeviceID == b.DeviceID || a.AuthPSK == b.AuthPSK || a.WGPrivateKey == b.WGPrivateKey {
		t.Fatal("two generated devices share secret/identity material")
	}
}
