// Package server assembles the gvpn server pipeline: it accepts connections,
// authenticates them in-tunnel, and runs ONE multiplexed WireGuard engine over
// all of them (one device, one TUN, many peers). A connection is either an
// existing device (auth -> session bind -> data path) or a new device enrolling
// in-band (auth -> enroll exchange -> data path). The server is the single
// runtime writer of the registry. Transport-agnostic: production supplies a
// GOST-TLS listener and a real TUN; tests use plain TCP and netstack. Pure Go.
package server

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/enroll"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/session"
	"github.com/g00dvin/gvpn/core/transport"
	"github.com/g00dvin/gvpn/core/wgengine"
	"golang.zx2c4.com/wireguard/tun"
)

// defaultSubnet is the tunnel subnet used for enrollment IP allocation when
// Config.Subnet is empty.
const defaultSubnet = "10.100.0.0/24"

// sweepInterval is how often expired sessions are reaped.
const sweepInterval = time.Minute

// Config holds the multiplexed server's WireGuard parameters.
type Config struct {
	WGPrivateKey wgengine.Key // server's WireGuard private key
	Subnet       string       // tunnel subnet for enrollment IP allocation; default 10.100.0.0/24
	LogLevel     int          // wireguard-go log level (device.LogLevel*)
}

func (c Config) subnetOrDefault() string {
	if c.Subnet == "" {
		return defaultSubnet
	}
	return c.Subnet
}

// Server accepts authenticated client connections and multiplexes them onto one
// WireGuard device. Serve is transport-agnostic; production passes a GOST-TLS
// listener, tests pass plain TCP.
type Server struct {
	gate     *authgate.Gate
	sessions *session.Manager
	store    *provision.FileStore
	cfg      Config
	eng      *wgengine.MuxEngine
	subnet   netip.Prefix

	mu        sync.Mutex
	conns     map[uint64]net.Conn
	nextID    uint64
	closed    bool
	sweepStop chan struct{}
	wg        sync.WaitGroup
}

// New builds a Server on a single TUN device. The gate must have been
// constructed with store as its DeviceStore so auth, enrollment, and the
// WG-pubkey lookups agree on the registry. It starts the session-sweep ticker.
func New(gate *authgate.Gate, sessions *session.Manager, store *provision.FileStore, cfg Config, tunDev tun.Device) (*Server, error) {
	subnet, err := netip.ParsePrefix(cfg.subnetOrDefault())
	if err != nil {
		return nil, err
	}
	eng, err := wgengine.NewMuxEngine(tunDev, cfg.WGPrivateKey, cfg.LogLevel)
	if err != nil {
		return nil, err
	}
	s := &Server{
		gate:      gate,
		sessions:  sessions,
		store:     store,
		cfg:       cfg,
		eng:       eng,
		subnet:    subnet,
		conns:     make(map[uint64]net.Conn),
		sweepStop: make(chan struct{}),
	}
	go s.sweepLoop()
	return s, nil
}

func (s *Server) sweepLoop() {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.sessions.Sweep()
		case <-s.sweepStop:
			return
		}
	}
}

// Serve accepts connections until ln returns an error (e.g. it is closed).
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.handle(conn)
	}
}

// handle runs one connection through the gate and dispatches by token kind.
func (s *Server) handle(conn net.Conn) {
	defer s.wg.Done()
	res, err := s.gate.Handle(conn)
	if err != nil || !res.Authenticated {
		return // the gate proxied to the decoy or closed the connection
	}
	switch res.Kind {
	case authgate.KindEnroll:
		s.handleEnroll(res.UserID, res.Conn)
	default:
		s.handleDevice(res.DeviceID, res.Conn)
	}
}

// handleDevice binds (or resumes) the session for an already-registered device,
// ensures its WireGuard peer, and runs the data path.
func (s *Server) handleDevice(deviceID [16]byte, conn net.Conn) {
	if _, err := s.sessions.Bind(deviceID, conn); err != nil {
		conn.Close()
		return
	}
	dev, ok := s.store.Device(deviceID)
	if !ok {
		conn.Close()
		return
	}
	pub, ok := s.store.WGPublicKey(deviceID)
	if !ok {
		conn.Close()
		return
	}
	if err := s.eng.AddPeer(pub, dev.TunnelIP+"/32"); err != nil {
		conn.Close()
		return
	}
	s.runDataPath(conn)
}

// handleEnroll provisions a brand-new device in-band: it checks the user's
// guardrails, reads the device's WG public key, allocates a tunnel IP + device
// id, mints a per-device PSK, persists the device (encrypted) and adds the live
// peer, replies with the credentials, then runs the data path. Any failure
// closes the connection with no distinguishing response.
func (s *Server) handleEnroll(userID [16]byte, conn net.Conn) {
	u, ok := s.store.UserByID(userID)
	if !ok || u.Disabled || !u.EnrollOpen {
		conn.Close()
		return
	}
	if u.DeviceCap > 0 && s.store.DeviceCount(u.Handle) >= u.DeviceCap {
		conn.Close()
		return
	}
	req, err := enroll.ReadRequest(conn)
	if err != nil {
		conn.Close()
		return
	}
	used := make([]netip.Addr, 0)
	for _, ipStr := range s.store.UsedIPs() {
		if a, err := netip.ParseAddr(ipStr); err == nil {
			used = append(used, a)
		}
	}
	ip, err := provision.AllocateIP(used, s.subnet)
	if err != nil {
		conn.Close()
		return
	}
	id, err := provision.NewDeviceID()
	if err != nil {
		conn.Close()
		return
	}
	psk, err := provision.NewAuthPSK()
	if err != nil {
		conn.Close()
		return
	}
	pub := wgengine.Key(req.WGPublic)
	dev := provision.Device{
		DeviceID: id.String(), User: u.Handle, WGPublic: pub.Hex(),
		TunnelIP: ip.String(), Source: "enroll",
	}
	if err := s.store.AddDevice(dev, psk); err != nil {
		conn.Close()
		return
	}
	if err := s.eng.AddPeer(pub, ip.String()+"/32"); err != nil {
		conn.Close()
		return
	}
	if err := enroll.WriteResponse(conn, enroll.Response{
		DeviceID: [16]byte(id), TunnelIP: ip.String(), DevicePSK: psk,
	}); err != nil {
		conn.Close()
		return
	}
	s.runDataPath(conn)
}

// runDataPath registers conn into the mux engine and blocks until the connection
// dies, then deregisters and closes it. notifyTransport signals death on the
// first read/write error or Close.
func (s *Server) runDataPath(conn net.Conn) {
	nt := newNotifyTransport(transport.NewStreamTransport(conn))
	id, ok := s.track(conn)
	if !ok {
		conn.Close() // server is shutting down
		return
	}
	s.eng.Register(id, nt)
	<-nt.Done()
	s.eng.Deregister(id)
	s.untrack(id)
	conn.Close()
}

// track records conn under a fresh connection id (>= 1), or returns false if the
// server is closing.
func (s *Server) track(conn net.Conn) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, false
	}
	s.nextID++
	id := s.nextID
	s.conns[id] = conn
	return id, true
}

func (s *Server) untrack(id uint64) {
	s.mu.Lock()
	delete(s.conns, id)
	s.mu.Unlock()
}

// Close stops accepting work, closes all live connections (unblocking their
// handlers), waits for the handlers to finish, then shuts the engine and the
// sweep ticker down. It is idempotent. The caller closes the listener.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	conns := make([]net.Conn, 0, len(s.conns))
	for _, c := range s.conns {
		conns = append(conns, c)
	}
	s.conns = make(map[uint64]net.Conn)
	s.mu.Unlock()

	close(s.sweepStop)
	for _, c := range conns {
		c.Close()
	}
	s.wg.Wait()
	return s.eng.Close()
}
