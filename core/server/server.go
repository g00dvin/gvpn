package server

import (
	"net"
	"sync"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/session"
	"github.com/g00dvin/gvpn/core/transport"
	"github.com/g00dvin/gvpn/core/wgengine"
	"golang.zx2c4.com/wireguard/tun"
)

// TunFactory creates a fresh TUN device for one client (a real kernel TUN in
// production; tun/netstack in tests).
type TunFactory func() (tun.Device, error)

// Config holds the server's per-client WireGuard parameters.
//
// Per-client-device model (phase 1): one wireguard-go device per connected
// client. This does NOT meet the 1000-client / 512MB budget; a single
// multiplexed device is a later optimization.
type Config struct {
	WGPrivateKey    wgengine.Key // server's WireGuard private key
	ClientAllowedIP string       // allowed_ip for each client peer; default "0.0.0.0/0"
	LogLevel        int          // wireguard-go log level (device.LogLevel*)
}

// Server accepts authenticated client connections and runs a per-client
// WireGuard engine over each. Serve is transport-agnostic: production passes a
// GOST-TLS listener; tests pass a plain TCP listener.
type Server struct {
	gate     *authgate.Gate
	sessions *session.Manager
	store    *provision.FileStore
	cfg      Config
	newTun   TunFactory

	mu      sync.Mutex
	clients map[*client]struct{}
	closed  bool
}

type client struct {
	eng  *wgengine.Engine
	once sync.Once
}

// close tears the client's engine down at most once (handle and Server.Close can
// race). eng.Close also closes the framed transport and thus the connection.
func (c *client) close() { c.once.Do(func() { c.eng.Close() }) }

// New builds a Server. The gate must have been constructed with store as its
// DeviceStore so auth and the WG-pubkey lookup agree on the device set.
func New(gate *authgate.Gate, sessions *session.Manager, store *provision.FileStore, cfg Config, newTun TunFactory) *Server {
	if cfg.ClientAllowedIP == "" {
		cfg.ClientAllowedIP = "0.0.0.0/0"
	}
	return &Server{
		gate:     gate,
		sessions: sessions,
		store:    store,
		cfg:      cfg,
		newTun:   newTun,
		clients:  make(map[*client]struct{}),
	}
}

// Serve accepts connections until ln returns an error (e.g. it is closed).
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

// handle runs one connection through the full pipeline.
func (s *Server) handle(conn net.Conn) {
	// 1. In-tunnel auth. On failure the gate has already proxied to the decoy or
	//    closed the connection.
	res, err := s.gate.Handle(conn)
	if err != nil || !res.Authenticated {
		return
	}
	// 2. Bind (new or resumed) session.
	if _, err := s.sessions.Bind(res.DeviceID, res.Conn); err != nil {
		res.Conn.Close()
		return
	}
	// 3. Resolve the device's registered WireGuard public key.
	peerPub, ok := s.store.WGPublicKey(res.DeviceID)
	if !ok {
		res.Conn.Close()
		return
	}
	// 4. Per-client TUN + WireGuard engine over the framed transport.
	tunDev, err := s.newTun()
	if err != nil {
		res.Conn.Close()
		return
	}
	nt := newNotifyTransport(transport.NewStreamTransport(res.Conn))
	eng, err := wgengine.New(tunDev, nt, wgengine.Config{
		PrivateKey:    s.cfg.WGPrivateKey,
		PeerPublicKey: peerPub,
		AllowedIPs:    []string{s.cfg.ClientAllowedIP},
	}, s.cfg.LogLevel)
	if err != nil {
		tunDev.Close()
		res.Conn.Close()
		return
	}
	// 5. Track for shutdown, then run until the connection dies.
	c := &client{eng: eng}
	if !s.track(c) {
		c.close() // server already closing
		return
	}
	<-nt.Done()
	s.untrack(c)
	c.close() // closes the device, bind reader, and the transport (=> the conn)
}

func (s *Server) track(c *client) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.clients[c] = struct{}{}
	return true
}

func (s *Server) untrack(c *client) {
	s.mu.Lock()
	delete(s.clients, c)
	s.mu.Unlock()
}

// Close tears down all active client engines. The caller closes the listener
// (which stops Serve's accept loop).
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	cs := make([]*client, 0, len(s.clients))
	for c := range s.clients {
		cs = append(cs, c)
	}
	s.clients = make(map[*client]struct{})
	s.mu.Unlock()
	for _, c := range cs {
		c.close()
	}
	return nil
}
