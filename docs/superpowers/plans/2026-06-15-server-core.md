# Server Core (per-client-device) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. `core/server` is **pure Go (no cgo)**; the `tun/netstack` import is **test-only** (keep it out of non-test files).
>
> **Per-task model assignment (standing rule):**
> - **Sonnet** subagent — implements each code task (Tasks 1–3).
> - **Opus** (controller) — manages tasks, reviews each diff; dispatches a fresh **Opus** subagent for the final code + security review (Task 4).
> - **Haiku** subagent — `gh` push + PR (Task 4).

**Goal:** Assemble the server pipeline that turns one accepted (GOST-TLS-terminated) connection into a running VPN tunnel: in-tunnel auth → session bind → a per-client WireGuard engine over the framed transport. Prove end-to-end that IP traffic flows through the server, client→server, over a real handshake.

**Architecture:** A new pure-Go `core/server` package. `Server.Serve(ln net.Listener)` accepts connections and, per connection, runs `handle`: `authgate.Gate.Handle` (unauthenticated/garbage is reverse-proxied to the decoy or closed inside the gate) → `session.Manager.Bind` (new/resume) → look up the client's WireGuard public key via `provision.FileStore.WGPublicKey` → wrap the conn in `transport.NewStreamTransport` and start a `wgengine.Engine` on a per-client TUN from an injected `TunFactory`. A `notifyTransport` wrapper signals when the connection dies so the engine is torn down. `Server` is **transport-agnostic**: production passes a `gosttls.Listen` listener (proven in Plan 3) and a real kernel TUN factory; tests pass a plain TCP listener and a `tun/netstack` factory — so `core/server` stays cgo-free and runs in CI without the GOST engine.

**Decisions (phase-1, deliberate — documented):**
- **Per-client wireguard-go device:** one `Engine`/`Bind`/TUN per connected client. Simple and directly composes the built pieces, and it is the user-chosen stepping-stone. **It does NOT meet the 1000-client / ≤512 MB budget** (~1000 devices is too heavy); a single multiplexed device + multiplexing Bind is a later optimization with its own design pass. Recorded here so the limitation is explicit.
- **No per-device IPAM in this plan:** each client connects to a *dedicated* device whose single peer uses `allowed_ip = 0.0.0.0/0`; the client's own tunnel IP lives client-side (tests use fixed IPs; the bundle/registry gain a tunnel-IP field when the client app and the multiplexed server land).
- **TUN injected via `TunFactory`** (`func() (tun.Device, error)`); the production kernel-TUN factory + the `gvpn-server` binary + `server.yaml` + routing/NAT are the next plan.

**Tech Stack:** Go 1.24, stdlib + the already-present `core/{authgate,session,provision,transport,wgengine}` and (test-only) `golang.zx2c4.com/wireguard/{tun,tun/netstack,device}`. Toolchain `/home/goodvin/.local/go/bin/go`. No cgo in `core/server`.

**Design reference:** `docs/superpowers/specs/2026-06-13-gvpn-transport-design.md` §2 (server data flow: TLS listener → auth gate → VPN data path / decoy), §5–§6.

---

## Conventions

- Toolchain: `/home/goodvin/.local/go/bin/go`. Run with: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./server/`.
- Branch `feat/server-core` off `main` (already created). Work from `/home/goodvin/git/gvpn`.
- Commits end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Module path `github.com/g00dvin/gvpn/core`.
- Keep `tun/netstack` (gVisor) confined to `_test.go` files.

## Existing APIs this plan builds on (verified against merged code)

- `transport.NewStreamTransport(io.ReadWriteCloser) *StreamTransport` — `ReadPacket` returns the next DATA-frame payload (skipping non-DATA frames), `WritePacket` writes a DATA frame, `Close` closes the underlying conn. Implements `transport.PacketTransport`.
- `authgate.NewGate(store authgate.DeviceStore, decoy authgate.Decoy) *Gate`; `(*Gate).Handle(conn net.Conn) (authgate.Result, error)`; `authgate.Result{Authenticated bool; DeviceID [16]byte; Conn net.Conn}`; `authgate.WriteAuth(conn net.Conn, psk []byte, deviceID [16]byte) error`.
- `session.NewManager(ttl time.Duration) *Manager`; `(*Manager).Bind(deviceID [16]byte, conn net.Conn) (*session.Session, error)`; `session.ClientBind(conn net.Conn, sid [16]byte, token [32]byte) ([16]byte, [32]byte, error)`.
- `provision.NewFileStore(path) (*FileStore, error)` (missing file ⇒ empty store, satisfies `authgate.DeviceStore`); `(*FileStore).WGPublicKey(deviceID [16]byte) (wgengine.Key, bool)`; `provision.Generate`, `provision.AppendDevice`, `provision.ParseDeviceID`, `provision.ParseKey`.
- `wgengine.New(tunDev tun.Device, pt transport.PacketTransport, cfg wgengine.Config, logLevel int) (*Engine, error)`; `wgengine.Config{PrivateKey, PeerPublicKey wgengine.Key; AllowedIPs []string; Keepalive int; Endpoint string}`; `(*Engine).Close() error`; `wgengine.GeneratePrivateKey`, `(Key).PublicKey`.

## File structure

```
core/server/transport.go        notifyTransport: PacketTransport wrapper that signals on conn death
core/server/transport_test.go
core/server/server.go           TunFactory, Config, Server, New, Serve, handle, Close
core/server/server_test.go      unauthenticated-conn + lifecycle test over plain TCP (no WG)
core/server/e2e_test.go         full-stack: client + Server over TCP + netstack, HTTP over tunnel
```

---

## Task 1: notifyTransport (connection-death signal)

**Files:** Create `core/server/transport.go`, `core/server/transport_test.go`.

- [ ] **Step 1: Write the failing test**

Create `core/server/transport_test.go`:
```go
package server

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// errTransport is a PacketTransport whose reads fail after a signal, for testing
// that notifyTransport fires Done on the first error.
type errTransport struct {
	mu       sync.Mutex
	failRead bool
	closed   bool
}

func (e *errTransport) ReadPacket() ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failRead {
		return nil, errors.New("read failed")
	}
	return []byte("pkt"), nil
}
func (e *errTransport) WritePacket(p []byte) error { return nil }
func (e *errTransport) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	return nil
}

func TestNotifyTransportSignalsOnReadError(t *testing.T) {
	inner := &errTransport{}
	nt := newNotifyTransport(inner)

	// A successful read does not signal.
	if _, err := nt.ReadPacket(); err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	select {
	case <-nt.Done():
		t.Fatal("Done fired after a successful read")
	default:
	}

	// The first failing read signals Done.
	inner.mu.Lock()
	inner.failRead = true
	inner.mu.Unlock()
	if _, err := nt.ReadPacket(); err == nil {
		t.Fatal("expected read error")
	}
	select {
	case <-nt.Done():
	case <-time.After(time.Second):
		t.Fatal("Done did not fire after a read error")
	}
}

func TestNotifyTransportSignalsOnClose(t *testing.T) {
	nt := newNotifyTransport(&errTransport{})
	if err := nt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-nt.Done():
	case <-time.After(time.Second):
		t.Fatal("Done did not fire after Close")
	}
	// Done is idempotent / single-close (calling Close again must not panic).
	if err := nt.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// notifyTransport must satisfy transport.PacketTransport (compile-time check via use).
var _ = net.Conn(nil)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./server/ -run TestNotifyTransport -v`
Expected: FAIL — `undefined: newNotifyTransport`.

- [ ] **Step 3: Write the implementation**

Create `core/server/transport.go`:
```go
// Package server assembles the gvpn server pipeline: it accepts connections,
// authenticates them in-tunnel, binds sessions, and runs a per-client WireGuard
// engine over the framed transport. It is transport-agnostic — production
// supplies a GOST-TLS listener and a real TUN; tests use plain TCP and netstack.
// Pure Go, no cgo.
package server

import (
	"sync"

	"github.com/g00dvin/gvpn/core/transport"
)

// notifyTransport wraps a PacketTransport and closes Done() the first time a
// read or write returns an error (or Close is called), so the server can tear
// down the client's WireGuard engine when the connection dies.
type notifyTransport struct {
	inner transport.PacketTransport
	once  sync.Once
	done  chan struct{}
}

var _ transport.PacketTransport = (*notifyTransport)(nil)

func newNotifyTransport(inner transport.PacketTransport) *notifyTransport {
	return &notifyTransport{inner: inner, done: make(chan struct{})}
}

// Done is closed once the connection has failed or been closed.
func (t *notifyTransport) Done() <-chan struct{} { return t.done }

func (t *notifyTransport) signal() { t.once.Do(func() { close(t.done) }) }

func (t *notifyTransport) ReadPacket() ([]byte, error) {
	p, err := t.inner.ReadPacket()
	if err != nil {
		t.signal()
	}
	return p, err
}

func (t *notifyTransport) WritePacket(p []byte) error {
	err := t.inner.WritePacket(p)
	if err != nil {
		t.signal()
	}
	return err
}

func (t *notifyTransport) Close() error {
	t.signal()
	return t.inner.Close()
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./server/ -run TestNotifyTransport -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./server/`.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/server/transport.go core/server/transport_test.go
git commit -m "feat(server): notifyTransport (connection-death signal)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Server core (Config, Serve, handle, Close)

**Files:** Create `core/server/server.go`, `core/server/server_test.go`.

- [ ] **Step 1: Write the failing test**

Create `core/server/server_test.go`:
```go
package server

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/session"
	"golang.zx2c4.com/wireguard/tun"
)

// An unauthenticated connection must be closed by the gate and must never reach
// the TUN factory / WireGuard setup; Server.Close must then return cleanly.
func TestServerClosesUnauthenticatedConn(t *testing.T) {
	store, err := provision.NewFileStore(filepath.Join(t.TempDir(), "empty.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	gate := authgate.NewGate(store, nil) // nil decoy => unauthenticated conns are closed
	sessions := session.NewManager(time.Minute)
	srv := New(gate, sessions, store, Config{}, func() (tun.Device, error) {
		t.Error("TunFactory must not be called for an unauthenticated connection")
		return nil, nil
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// Not a valid AUTH frame -> the gate closes the connection.
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 16)); err == nil {
		t.Fatal("server did not close the unauthenticated connection")
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./server/ -run TestServerClosesUnauthenticated -v`
Expected: FAIL — `undefined: New`, `undefined: Config`.

- [ ] **Step 3: Write the implementation**

Create `core/server/server.go`:
```go
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./server/ -run TestServerClosesUnauthenticated -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./server/`.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/server/server.go core/server/server_test.go
git commit -m "feat(server): per-client pipeline (gate -> session -> wgengine)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: End-to-end tunnel through the server

**Files:** Create `core/server/e2e_test.go`.

A provisioned device's bundle drives a real client (auth → session bind → WireGuard over the conn); the `Server` runs the matching pipeline; an HTTP GET flows over the tunnel to a service on the server's netstack. Plain TCP carries the transport (GOST TLS is the production outer layer, proven in Plan 3); `tun/netstack` is test-only.

- [ ] **Step 1: Write the test**

Create `core/server/e2e_test.go`:
```go
package server

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/session"
	"github.com/g00dvin/gvpn/core/transport"
	"github.com/g00dvin/gvpn/core/wgengine"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestServerEndToEndTunnelHTTP(t *testing.T) {
	serverWG, _ := wgengine.GeneratePrivateKey()
	serverTunIP := netip.MustParseAddr("192.168.4.1")
	clientTunIP := netip.MustParseAddr("192.168.4.2")

	// Provision a device and register it where the server's store will load it.
	bundle, deviceRec, err := provision.Generate(provision.GenerateParams{
		ServerWGPublicKey: serverWG.PublicKey(),
		ServerEndpoint:    "vpn.example.com:443",
		ServerName:        "vpn.example.com",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	reg := filepath.Join(t.TempDir(), "devices.json")
	if err := provision.AppendDevice(reg, deviceRec); err != nil {
		t.Fatalf("AppendDevice: %v", err)
	}
	store, err := provision.NewFileStore(reg)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	// The server's per-client TUN factory creates a netstack device and hands the
	// test its *netstack.Net so we can run a service on the server tunnel IP.
	netCh := make(chan *netstack.Net, 1)
	newTun := func() (tun.Device, error) {
		dev, n, err := netstack.CreateNetTUN([]netip.Addr{serverTunIP}, nil, 1420)
		if err == nil {
			netCh <- n
		}
		return dev, err
	}

	srv := New(
		authgate.NewGate(store, nil),
		session.NewManager(time.Minute),
		store,
		Config{WGPrivateKey: serverWG, LogLevel: device.LogLevelSilent},
		newTun,
	)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	// --- Client side: dial, authenticate, bind a session, start WireGuard. ---
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	psk, _ := hex.DecodeString(bundle.AuthPSK)
	devID, _ := provision.ParseDeviceID(bundle.DeviceID)
	if err := authgate.WriteAuth(conn, psk, devID); err != nil {
		t.Fatalf("WriteAuth: %v", err)
	}
	var zsid [16]byte
	var ztok [32]byte
	if _, _, err := session.ClientBind(conn, zsid, ztok); err != nil {
		t.Fatalf("ClientBind: %v", err)
	}

	clientPriv, _ := provision.ParseKey(bundle.WGPrivateKey)
	clientTun, clientNet, err := netstack.CreateNetTUN([]netip.Addr{clientTunIP}, nil, 1420)
	if err != nil {
		t.Fatalf("client CreateNetTUN: %v", err)
	}
	clientEng, err := wgengine.New(clientTun, transport.NewStreamTransport(conn), wgengine.Config{
		PrivateKey:    clientPriv,
		PeerPublicKey: serverWG.PublicKey(),
		AllowedIPs:    []string{"0.0.0.0/0"},
		Endpoint:      "server:0", // placeholder; arms the client handshake
		Keepalive:     5,
	}, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("client wgengine: %v", err)
	}
	defer clientEng.Close()

	// --- HTTP service on the server's tunnel IP (via the captured netstack). ---
	var serverNet *netstack.Net
	select {
	case serverNet = <-netCh:
	case <-time.After(10 * time.Second):
		t.Fatal("server never created its per-client TUN (auth/bind failed?)")
	}
	httpLn, err := serverNet.ListenTCP(&net.TCPAddr{IP: serverTunIP.AsSlice(), Port: 80})
	if err != nil {
		t.Fatalf("netstack ListenTCP: %v", err)
	}
	httpSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello through the gvpn server")
	})}
	go httpSrv.Serve(httpLn)
	defer httpSrv.Close()

	// --- Client GETs the service over the tunnel; retry while the handshake converges. ---
	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: clientNet.DialContext},
		Timeout:   2 * time.Second,
	}
	deadline := time.Now().Add(20 * time.Second)
	var body []byte
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get("http://192.168.4.1/")
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		break
	}
	if string(body) != "hello through the gvpn server" {
		t.Fatalf("tunnel HTTP body = %q, want the greeting (pipeline/handshake failed)", body)
	}

	_ = context.Background
}
```

- [ ] **Step 2: Run the test**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./server/ -run TestServerEndToEndTunnelHTTP -v -timeout 90s`
Expected: PASS — the client authenticates, binds a session, the server starts its per-client WireGuard engine, the handshake completes, and the HTTP GET returns the greeting over the tunnel.

If it FAILS or hangs, this is a real integration problem (report BLOCKED with diagnosis; you may temporarily set `device.LogLevelVerbose` on both engines to see handshake logs, then restore Silent). Do not weaken the assertion. Common checks: the client must send AUTH then SESSION_BIND (in that order, raw frames) before starting its wgengine; the client engine needs `Endpoint` set; both sides use `transport.NewStreamTransport` over the same conn for the DATA phase.

- [ ] **Step 3: Stability**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race -count=3 ./server/ -timeout 180s`
Expected: PASS all three. Report if flaky.

- [ ] **Step 4: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/server/e2e_test.go
git commit -m "test(server): end-to-end tunnel through the server pipeline

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Final review + PR

**Files:** none (verification + PR only).

- [ ] **Step 1: Whole-repo verification**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test -race ./server/
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test -race ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go build ./...
```
Expected: all PASS / clean.

- [ ] **Step 2: Confirm `core/server` is cgo-free and netstack is test-only**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go list -deps ./server/ | grep -iE 'netstack|gvisor' || echo "OK: clean non-test graph"`
Expected: `OK` (netstack/gVisor appear only under `go list -test -deps`).

- [ ] **Step 3: Opus final code + security review** (controller dispatches a fresh Opus subagent)

Review focus: pipeline ordering (auth → session → WG-pubkey → engine); every early-return path closes the connection exactly once and never leaks a TUN/engine; `Close` tears down all tracked clients without deadlock or double-close (note `eng.Close` also closes the conn via the transport); the `track`/`untrack`/`closed` race is correct under `-race`; an unauthenticated/garbage conn never reaches the TUN factory; no secret (PSK/WG key) logging; `tun/netstack` is test-only.

- [ ] **Step 4: Push and open PR** (trivial / `gh` — Haiku)

```bash
cd /home/goodvin/git/gvpn
git push -u origin feat/server-core
gh pr create --base main --head feat/server-core \
  --title "Server core: per-client pipeline (auth -> session -> WireGuard)" \
  --body "Assembles the server data flow (design §2): accept -> authgate.Gate -> session.Manager.Bind -> per-client wgengine.Engine over the framed transport. Proven end-to-end: a provisioned client authenticates, binds a session, completes a WireGuard handshake, and serves HTTP over the tunnel through the Server pipeline (-race).

- core/server/transport.go: notifyTransport — signals connection death so the engine is torn down.
- core/server/server.go: Config, Server, Serve (accept loop), handle (the pipeline), Close (lifecycle).
- Transport-agnostic: Serve takes a net.Listener (production injects gosttls.Listen; tests use TCP) and a TunFactory (production: real kernel TUN; tests: tun/netstack). core/server is pure Go; netstack is test-only.

PHASE-1 DECISION (documented): per-client wireguard-go device — simple and composable, but it does NOT meet the 1000-client/512MB budget; a single multiplexed device + multiplexing Bind is a later optimization. No per-device IPAM yet (dedicated device per client, allowed_ip 0.0.0.0/0; client tunnel IPs are fixed in tests).

Out of scope (next plans): the multiplexed-device server for the perf budget; the gvpn-server binary + server.yaml + real kernel TUN + routing/NAT; client app TUN integration (gomobile).

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

---

## Self-Review

**Spec coverage (design §2):** server accepts → auth gate (VPN vs decoy) → session bind → VPN data path (wireguard-go) → Tasks 2 (pipeline) + 3 (e2e proof). Decoy handled inside the gate (reused). Transport-agnostic listener lets the production binary inject `gosttls.Listen` (Plan 3) — wiring + real TUN + `server.yaml` are the next plan, explicitly out of scope.

**Placeholder scan:** none — full code for `notifyTransport`, the `Server`, and the e2e test. (The lone `_ = context.Background` keeps the import tidy if a future edit drops the context use; the implementer may remove `context` entirely if unused — adjust imports to compile cleanly.)

**Type consistency:** `notifyTransport` implements `transport.PacketTransport` (asserted) + `Done()`; `TunFactory = func() (tun.Device, error)`; `Config{WGPrivateKey wgengine.Key; ClientAllowedIP string; LogLevel int}`; `New(*authgate.Gate, *session.Manager, *provision.FileStore, Config, TunFactory) *Server`; `Serve(net.Listener) error`; `Close() error`. All called APIs match the merged signatures verified above (`Gate.Handle`→`Result{Authenticated,DeviceID,Conn}`, `Manager.Bind(deviceID,conn)`, `FileStore.WGPublicKey`, `wgengine.New(tun,pt,Config,logLevel)`, `transport.NewStreamTransport`).

**Concurrency note for the review:** `handle` runs per-connection; `track`/`untrack`/`Close` guard `clients` + `closed` under `s.mu`. `eng.Close()` can be reached from two places — `handle` (after `nt.Done()`) and `Close` (over the tracked snapshot) — which legitimately race when a client disconnects as the server shuts down; the per-client `sync.Once` in `client.close()` makes the actual teardown happen exactly once. A client that connects after `closed` is set gets `track`→false and is closed immediately (no leak). Verify under `-race` that there is no double-teardown and no engine/TUN leak on either path.
