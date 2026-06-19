package wgengine

import (
	"fmt"
	"strings"

	"github.com/g00dvin/gvpn/core/transport"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// MuxEngine drives ONE wireguard-go device over MANY connections via MuxBind:
// one device, one TUN, many peers. Peers are added incrementally and kept across
// disconnects so a WG session resumes when a peer reconnects on a new
// connection. The TUN device is supplied by the caller.
type MuxEngine struct {
	dev  *device.Device
	bind *MuxBind
}

// NewMuxEngine builds and starts a multiplexed engine: it creates a device on
// tunDev driven by a MuxBind, sets only the private key, and brings it up. Peers
// are added later with AddPeer. logLevel is one of
// device.LogLevelSilent/Error/Verbose.
func NewMuxEngine(tunDev tun.Device, privKey Key, logLevel int) (*MuxEngine, error) {
	bind := NewMuxBind()
	dev := device.NewDevice(tunDev, bind, device.NewLogger(logLevel, "gvpn-wg-mux: "))
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\n", privKey.Hex())); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wgengine: mux IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wgengine: mux device up: %w", err)
	}
	return &MuxEngine{dev: dev, bind: bind}, nil
}

// AddPeer adds (or idempotently updates) a peer by public key with exactly one
// allowed IP (its tunnel /32). It is safe to call again on reconnect; the peer
// and its crypto session are preserved across Deregister/Register.
func (e *MuxEngine) AddPeer(pub Key, allowedIP string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", pub.Hex())
	fmt.Fprintf(&b, "replace_allowed_ips=true\n")
	fmt.Fprintf(&b, "allowed_ip=%s\n", allowedIP)
	if err := e.dev.IpcSet(b.String()); err != nil {
		return fmt.Errorf("wgengine: AddPeer: %w", err)
	}
	return nil
}

// RemovePeer removes a peer (revocation). Removing an unknown peer is a no-op.
func (e *MuxEngine) RemovePeer(pub Key) error {
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", pub.Hex())
	fmt.Fprintf(&b, "remove=true\n")
	if err := e.dev.IpcSet(b.String()); err != nil {
		return fmt.Errorf("wgengine: RemovePeer: %w", err)
	}
	return nil
}

// Register attaches connection id (backed by pt) to the bind so its inbound
// packets reach the device and outbound packets for peers last seen on it route
// back.
func (e *MuxEngine) Register(id uint64, pt transport.PacketTransport) { e.bind.Register(id, pt) }

// Deregister detaches connection id (the peer stays configured for reconnect).
func (e *MuxEngine) Deregister(id uint64) { e.bind.Deregister(id) }

// Close shuts the device down and releases all reader goroutines. It does not
// own the registered connections, but Shutdown closes them to unblock readers
// during teardown. The order matters: dev.Close stops the receive func draining
// the bind's recv channel first, so Shutdown's dead signal then releases any
// reader parked on a full recv send without a deadlock.
func (e *MuxEngine) Close() error {
	e.dev.Close()     // ends the bind's receive funcs (stops draining recv)
	e.bind.Shutdown() // releases readers, closes registered transports
	return nil
}
