// Package mobile is the gomobile-bindable client tunnel API: it composes the
// gvpn transport + WireGuard core into Connect/Disconnect over a host-provided
// TUN file descriptor, for the Android and iOS clients. The Go layer is stateless
// (the host owns credential storage). cgo lives underneath in gosttls; the
// exported surface uses only gomobile-bindable types.
package mobile

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/gosttls"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/session"
	"github.com/g00dvin/gvpn/core/transport"
	"github.com/g00dvin/gvpn/core/wgengine"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// tunMTU is the WireGuard tunnel MTU.
const tunMTU = 1420

// StatusReporter is implemented by the host to receive tunnel lifecycle events.
// gomobile binds it as a callback class (Kotlin/Swift). Messages contain no
// secrets.
type StatusReporter interface {
	OnState(state string)   // "connecting","connected","reconnecting","disconnected"
	OnError(message string) // human-readable failure description
}

// Tunnel is an opaque, bound handle to one running tunnel.
type Tunnel struct {
	eng       *wgengine.Engine
	reporter  StatusReporter
	closeOnce sync.Once
}

// clientConfig is a parsed, validated device bundle ready to build a tunnel.
type clientConfig struct {
	deviceID   [16]byte
	authPSK    []byte
	wgPriv     wgengine.Key
	serverPub  wgengine.Key
	endpoint   string
	serverName string
	caPEM      string
}

// parseBundle parses and validates a provision.Bundle JSON into a clientConfig.
func parseBundle(bundleJSON string) (clientConfig, error) {
	b, err := provision.ParseBundle([]byte(bundleJSON))
	if err != nil {
		return clientConfig{}, err
	}
	id, err := provision.ParseDeviceID(b.DeviceID)
	if err != nil {
		return clientConfig{}, fmt.Errorf("mobile: device_id: %w", err)
	}
	psk, err := hex.DecodeString(b.AuthPSK)
	if err != nil {
		return clientConfig{}, fmt.Errorf("mobile: auth_psk: %w", err)
	}
	priv, err := provision.ParseKey(b.WGPrivateKey)
	if err != nil {
		return clientConfig{}, fmt.Errorf("mobile: wg_private_key: %w", err)
	}
	pub, err := provision.ParseKey(b.ServerWGPublicKey)
	if err != nil {
		return clientConfig{}, fmt.Errorf("mobile: server_wg_public_key: %w", err)
	}
	if b.ServerEndpoint == "" {
		return clientConfig{}, fmt.Errorf("mobile: server_endpoint is empty")
	}
	if b.ServerName == "" {
		// Required so the GOST TLS dial enforces hostname verification (SSL_set1_host),
		// not just chain-to-CA. The bundle always carries it.
		return clientConfig{}, fmt.Errorf("mobile: server_name is empty")
	}
	return clientConfig{
		deviceID: id, authPSK: psk, wgPriv: priv, serverPub: pub,
		endpoint: b.ServerEndpoint, serverName: b.ServerName, caPEM: b.ServerCAPEM,
	}, nil
}

// handshake writes the in-tunnel AUTH frame and runs the SESSION_BIND exchange
// (a fresh zero-bind) on conn, leaving it positioned at the WireGuard data path.
// It is shared by the production GOST dialer and the plain-TCP test dialer.
func handshake(conn net.Conn, cc clientConfig) error {
	if err := authgate.WriteAuth(conn, cc.authPSK, cc.deviceID); err != nil {
		return err
	}
	var zsid [16]byte
	var ztok [32]byte
	if _, _, err := session.ClientBind(conn, zsid, ztok); err != nil {
		return err
	}
	return nil
}

// gostDialer is the production handshake dialer: GOST TLS -> AUTH -> SESSION_BIND.
func gostDialer(cc clientConfig) transport.Dialer {
	return func(ctx context.Context) (io.ReadWriteCloser, error) {
		conn, err := gosttls.Dial(ctx, "tcp", cc.endpoint, gosttls.Config{
			CAPEM: cc.caPEM, ServerName: cc.serverName,
		})
		if err != nil {
			return nil, err
		}
		if err := handshake(conn, cc); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

// Connect brings up a tunnel for an already-enrolled device described by
// bundleJSON, running WireGuard over the host TUN file descriptor tunFD, and
// reports lifecycle changes to reporter. The data path runs in the background.
func Connect(bundleJSON string, tunFD int, reporter StatusReporter) (*Tunnel, error) {
	reporter.OnState("connecting")
	cc, err := parseBundle(bundleJSON)
	if err != nil {
		reporter.OnError(err.Error())
		return nil, err
	}
	tunFile := os.NewFile(uintptr(tunFD), "gvpn-tun")
	if tunFile == nil {
		err := fmt.Errorf("mobile: invalid tun fd %d", tunFD)
		reporter.OnError(err.Error())
		return nil, err
	}
	tunDev, err := tun.CreateTUNFromFile(tunFile, tunMTU)
	if err != nil {
		reporter.OnError(err.Error())
		return nil, err
	}
	t, err := newTunnel(cc, tunDev, gostDialer(cc), reporter)
	if err != nil {
		tunDev.Close()
		reporter.OnError(err.Error())
		return nil, err
	}
	return t, nil
}

// newTunnel wires a reconnecting transport + WireGuard engine over tunDev, using
// dial as the (re)connect handshake. dial is injectable so tests drive it over
// plain TCP. On success it reports "connected" and returns a live Tunnel.
func newTunnel(cc clientConfig, tunDev tun.Device, dial transport.Dialer, reporter StatusReporter) (*Tunnel, error) {
	rt := transport.NewReconnectingTransport(transport.ReconnectingConfig{Dialer: dial})
	eng, err := wgengine.New(tunDev, rt, wgengine.Config{
		PrivateKey:    cc.wgPriv,
		PeerPublicKey: cc.serverPub,
		AllowedIPs:    []string{"0.0.0.0/0"},
		Endpoint:      "gvpn-server:0",
		Keepalive:     25,
	}, device.LogLevelSilent)
	if err != nil {
		rt.Close() // release the reconnecting transport's reader if the bind opened
		return nil, err
	}
	reporter.OnState("connected")
	return &Tunnel{eng: eng, reporter: reporter}, nil
}

// Disconnect tears the tunnel down (engine -> bind -> transport -> TUN) exactly
// once and reports "disconnected".
func (t *Tunnel) Disconnect() error {
	var err error
	t.closeOnce.Do(func() {
		err = t.eng.Close()
		t.reporter.OnState("disconnected")
	})
	return err
}
