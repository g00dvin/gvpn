package wgengine

import (
	"fmt"
	"strings"

	"github.com/g00dvin/gvpn/core/transport"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Config configures one WireGuard endpoint.
type Config struct {
	PrivateKey    Key      // this endpoint's private key
	PeerPublicKey Key      // the single peer's public key
	AllowedIPs    []string // CIDRs allowed from/to the peer, e.g. "0.0.0.0/0"
	Keepalive     int      // persistent keepalive seconds (0 = disabled)
	// Endpoint, when non-empty, arms this side to initiate the handshake
	// (clients set it; servers leave it empty). The value is a placeholder —
	// the Bind ignores it — but must be non-empty on the initiator.
	Endpoint string
}

// uapi renders the WireGuard UAPI configuration. listen_port is deliberately
// omitted (the transport has no UDP port).
func (c Config) uapi() string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", c.PrivateKey.Hex())
	fmt.Fprintf(&b, "public_key=%s\n", c.PeerPublicKey.Hex())
	for _, cidr := range c.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", cidr)
	}
	if c.Endpoint != "" {
		fmt.Fprintf(&b, "endpoint=%s\n", c.Endpoint)
	}
	if c.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", c.Keepalive)
	}
	return b.String()
}

// Engine embeds a wireguard-go device whose outside traffic flows over a
// transport.PacketTransport via Bind. The TUN device is supplied by the caller.
type Engine struct {
	dev  *device.Device
	bind *Bind
	pt   transport.PacketTransport
}

// New builds and starts a WireGuard engine: it wraps pt in a Bind, creates a
// device on tunDev, applies cfg, and brings it up. logLevel is one of
// device.LogLevelSilent/Error/Verbose.
func New(tunDev tun.Device, pt transport.PacketTransport, cfg Config, logLevel int) (*Engine, error) {
	bind := NewBind(pt)
	dev := device.NewDevice(tunDev, bind, device.NewLogger(logLevel, "gvpn-wg: "))

	if err := dev.IpcSet(cfg.uapi()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wgengine: IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wgengine: device up: %w", err)
	}
	return &Engine{dev: dev, bind: bind, pt: pt}, nil
}

// Close shuts down the device, releases the bind's background reader, and closes
// the transport.
func (e *Engine) Close() error {
	e.dev.Close()       // calls bind.Close(); waits for receive funcs to stop
	e.bind.stopReader() // release a reader blocked delivering to recv
	return e.pt.Close() // unblock a reader blocked on ReadPacket
}
