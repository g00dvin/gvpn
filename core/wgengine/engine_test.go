package wgengine

import (
	"net"
	"net/netip"
	"testing"

	"github.com/g00dvin/gvpn/core/transport"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestEngineUpAndClose(t *testing.T) {
	priv, _ := GeneratePrivateKey()
	peer, _ := GeneratePrivateKey()

	tunDev, _, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("192.168.4.1")}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}

	c1, c2 := net.Pipe()
	defer c2.Close()
	pt := transport.NewStreamTransport(c1)

	eng, err := New(tunDev, pt, Config{
		PrivateKey:    priv,
		PeerPublicKey: peer.PublicKey(),
		AllowedIPs:    []string{"192.168.4.2/32"},
	}, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
