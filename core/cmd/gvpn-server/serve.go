package main

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/server"
	"github.com/g00dvin/gvpn/core/session"
	"golang.zx2c4.com/wireguard/tun"
)

// sessionTTL is how long a disconnected session may be resumed.
const sessionTTL = 5 * time.Minute

// serveDeps are the injectable host seams: a listener (GOST TLS in prod, plain
// TCP in tests), a TUN factory (real kernel TUN in prod, netstack in tests), and
// the NAT installer. LogLevel is the wireguard-go log level.
type serveDeps struct {
	Listener net.Listener
	NewTUN   func(addrCIDR string) (tun.Device, error)
	NAT      NAT
	LogLevel int
}

// run assembles the server pipeline from cfg + deps and serves until the
// listener is closed, then tears down (engine close + NAT disable).
func run(cfg Config, deps serveDeps) error {
	key, err := provision.LoadMasterKey(cfg.MasterKeyFile)
	if err != nil {
		return err
	}
	cipher, err := provision.NewCipher(key)
	if err != nil {
		return err
	}
	store, err := provision.NewFileStore(cfg.Registry, cipher)
	if err != nil {
		return err
	}
	wgPriv, err := provision.ParseKey(cfg.WireGuard.PrivateKey)
	if err != nil {
		return fmt.Errorf("gvpn-server: wireguard.private_key: %w", err)
	}

	tunDev, err := deps.NewTUN(cfg.WireGuard.Address)
	if err != nil {
		return fmt.Errorf("gvpn-server: create TUN: %w", err)
	}

	gate := authgate.NewGate(store, nil)
	sessions := session.NewManager(sessionTTL)
	srv, err := server.New(gate, sessions, store, server.Config{
		WGPrivateKey: wgPriv,
		Subnet:       cfg.Subnet(),
		LogLevel:     deps.LogLevel,
	}, tunDev)
	if err != nil {
		tunDev.Close()
		return err
	}

	if err := deps.NAT.Enable(cfg.Subnet()); err != nil {
		srv.Close()
		return fmt.Errorf("gvpn-server: enable NAT: %w", err)
	}
	defer deps.NAT.Disable(cfg.Subnet())
	defer srv.Close()

	// Serve blocks until the listener is closed; it returns that error.
	return srv.Serve(deps.Listener)
}

// realTUN creates a kernel TUN device named gvpn0, assigns addrCIDR, and brings
// it up. It shells out to `ip` (CAP_NET_ADMIN). Production NewTUN.
func realTUN(addrCIDR string) (tun.Device, error) {
	if _, err := netip.ParsePrefix(addrCIDR); err != nil {
		return nil, fmt.Errorf("gvpn-server: address %q: %w", addrCIDR, err)
	}
	dev, err := tun.CreateTUN("gvpn0", 1420)
	if err != nil {
		return nil, err
	}
	name, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, err
	}
	for _, args := range [][]string{
		{"addr", "add", addrCIDR, "dev", name},
		{"link", "set", "dev", name, "up"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			dev.Close()
			return nil, fmt.Errorf("gvpn-server: ip %v: %w: %s", args, err, out)
		}
	}
	return dev, nil
}
