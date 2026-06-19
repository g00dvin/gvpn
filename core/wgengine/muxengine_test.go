package wgengine

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestMuxEngineAddRemovePeerAndClose(t *testing.T) {
	priv, _ := GeneratePrivateKey()
	tunDev, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.100.0.1")}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	eng, err := NewMuxEngine(tunDev, priv, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("NewMuxEngine: %v", err)
	}

	peer, _ := GeneratePrivateKey()
	if err := eng.AddPeer(peer.PublicKey(), "10.100.0.2/32"); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	// AddPeer is idempotent (re-adding the same peer must not error).
	if err := eng.AddPeer(peer.PublicKey(), "10.100.0.2/32"); err != nil {
		t.Fatalf("AddPeer (idempotent): %v", err)
	}
	if err := eng.RemovePeer(peer.PublicKey()); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
