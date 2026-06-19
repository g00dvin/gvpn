# Multiplexed Server + Enrollment Handler Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Per-task model assignment (standing rule):** **Sonnet** subagent implements each code task; **Opus** (controller) manages tasks and reviews each diff, and dispatches a fresh **Opus** subagent for the final review; **Haiku** subagent does the `gh` push + PR.

**Goal:** Rewrite `core/server.Server` from the per-client-device model to the multiplexed `wgengine.MuxEngine` (one device, one TUN, many peers), branch the post-gate pipeline on the AUTH token kind, and add the in-band dynamic-enrollment handler that provisions a new device live (allocate IP + DeviceID, mint PSK, persist, `AddPeer`, reply) — finally wiring together the Plan 10 enrollment primitives and the Plan 11 multiplexed engine.

**Architecture:** `Server` owns one `MuxEngine` built on a single injected `tun.Device`. `handle(conn)` runs the gate, then branches: **device** path → `sessions.Bind` → look up the device's registered pubkey + tunnel IP → `MuxEngine.AddPeer(pub, ip/32)` → register the connection into the mux for the data path; **enroll** path → guardrails (user enabled, enrollment open, device cap) → read the device's WG pubkey → allocate a tunnel IP + DeviceID, mint a per-device PSK, `FileStore.AddDevice` (persist, encrypted) + `MuxEngine.AddPeer` (live) → reply → register the connection. A monotonic connection id (never 0) names each connection in the mux; a session-sweep ticker reaps expired sessions. The server is the single runtime writer of the registry. Pure Go; cgo-free; the GOST-TLS listener and real kernel TUN are injected by the binary (next plan).

**Tech Stack:** Go 1.24, `golang.zx2c4.com/wireguard` (device/tun/netstack for tests), stdlib. Toolchain `/home/goodvin/.local/go/bin/go`. Module `github.com/g00dvin/gvpn/core`.

**Design reference:** `docs/superpowers/specs/2026-06-16-user-identity-enrollment-admin-design.md` §7 (dynamic enrollment), §9 (multiplexed server data path). Consumes the merged Plan 10 (`authgate` kind/`Result.Kind`/`Result.UserID`, `core/enroll`) and Plan 11 (`wgengine.MuxEngine`).

---

## Conventions

- Toolchain: `/home/goodvin/.local/go/bin/go`. Run with `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./server/ ./provision/`.
- Branch `feat/mux-server` off `main` (already created; this plan doc is committed there).
- Commits end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- `.gitignore` already covers stray binaries / `go.work.sum` / `*.gvpn` / `registry.json`. Only `git add` the files each task names.
- **Breaking (internal API):** `server.New` changes signature (takes one `tun.Device`, returns `(*Server, error)`); `Config` drops `ClientAllowedIP`, gains `Subnet`; the `TunFactory` and per-client `client` type are removed. No external consumers yet (the binary is the next plan), so all callers are in-repo tests updated here.

## Decisions locked for this plan

- **One TUN injected at construction:** `New(gate, sessions, store, cfg, tunDev tun.Device) (*Server, error)` builds one `MuxEngine`. The caller (test/binary) creates the TUN with the server tunnel IP (e.g. `10.100.0.1`).
- **Per-peer allowed-IP:** each peer's allowed IP is the device's own `TunnelIP/32` (from the registry for the device path; freshly allocated for enrollment), NOT `0.0.0.0/0` — the device must route return packets to the correct peer.
- **Connection ids:** a monotonic `uint64` counter; the first id is `1` (id `0` is never a live connection, matching `MuxBind.ParseEndpoint`'s zero-id drop).
- **Enroll path has no SESSION_BIND:** the first (enrollment) connect goes gate → enroll exchange → data path. Subsequent connects use the normal device path (kind=DEVICE + SESSION_BIND). This matches design §7 ("bring up its tunnel; proceed as a normal client").
- **Guardrails enforced here** (the Plan 10 review carry-over): reject enrollment when the user is missing/`Disabled`/`!EnrollOpen`, or when `DeviceCap > 0 && DeviceCount >= DeviceCap` (`DeviceCap == 0` ⇒ unlimited). On any rejection or error the connection is simply closed (no distinguishing response).
- **Session sweep:** a background ticker calls `Manager.Sweep()` (the Plan 8 review carry-over), stopped on `Close`.
- **Provision additions:** `FileStore.UserByID(id)` (resolve the gate's verified UserID → user) and `provision.NewAuthPSK()` (mint a per-device PSK) — small, additive.

## File structure

```
core/provision/store.go         + FileStore.UserByID                                            (MODIFY)
core/provision/store_test.go    + UserByID test                                                 (MODIFY)
core/provision/provision.go     + NewAuthPSK                                                     (MODIFY)
core/provision/provision_test.go+ NewAuthPSK test                                                (MODIFY)
core/server/server.go           REWRITE: MuxEngine, kind branch, device + enroll handlers, sweep (REWRITE)
core/server/server_test.go      update to New(...,tunDev)(*Server,error)                         (MODIFY)
core/server/e2e_test.go         update device-path e2e to the multiplexed server                 (REWRITE)
core/server/enroll_e2e_test.go  self-enroll-on-first-connect e2e (no pre-provisioning)           (CREATE)
```

---

## Task 1: provision helpers (UserByID, NewAuthPSK)

**Files:** Modify `core/provision/store.go`, `core/provision/store_test.go`, `core/provision/provision.go`, `core/provision/provision_test.go`.

- [ ] **Step 1: Write the failing tests**

Append to `core/provision/store_test.go`:
```go
func TestFileStoreUserByID(t *testing.T) {
	fs, _ := newTestStore(t)
	u, _, err := fs.AddUser("dora")
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	id, err := ParseDeviceID(u.ID)
	if err != nil {
		t.Fatalf("ParseDeviceID: %v", err)
	}
	got, ok := fs.UserByID(id)
	if !ok || got.Handle != "dora" {
		t.Fatalf("UserByID = %+v,%v want dora", got, ok)
	}
	if _, ok := fs.UserByID([16]byte{0xFF}); ok {
		t.Fatal("UserByID unknown id: ok = true")
	}
}
```

Append to `core/provision/provision_test.go`:
```go
func TestNewAuthPSK(t *testing.T) {
	a, err := NewAuthPSK()
	if err != nil {
		t.Fatalf("NewAuthPSK: %v", err)
	}
	if len(a) != authPSKSize {
		t.Fatalf("psk len = %d, want %d", len(a), authPSKSize)
	}
	b, _ := NewAuthPSK()
	if string(a) == string(b) {
		t.Fatal("NewAuthPSK must return a fresh random key each call")
	}
}
```

- [ ] **Step 2: Run to confirm FAIL**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./provision/ -run 'TestFileStoreUserByID|TestNewAuthPSK' -v`
Expected: build error — `undefined: ... UserByID` / `undefined: NewAuthPSK`.

- [ ] **Step 3a: Add `UserByID` to `core/provision/store.go`**

Insert this method immediately after the existing `User(handle string)` method:
```go
// UserByID returns the user whose 16-byte id matches userID. The server's
// enrollment handler resolves the gate's verified UserID (from a KindEnroll
// token) to the owning user.
func (s *FileStore) UserByID(userID [16]byte) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.reg.Users {
		if id, err := ParseDeviceID(u.ID); err == nil && id == userID {
			return u, true
		}
	}
	return User{}, false
}
```

- [ ] **Step 3b: Add `NewAuthPSK` to `core/provision/provision.go`**

Insert after the `Generate` function (the file already imports `crypto/rand` and `io`):
```go
// NewAuthPSK returns a fresh random per-device AUTH PSK. The server mints one for
// each dynamically enrolled device (the CLI path uses Generate instead).
func NewAuthPSK() ([]byte, error) {
	psk := make([]byte, authPSKSize)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		return nil, err
	}
	return psk, nil
}
```

- [ ] **Step 4: Run to confirm PASS**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test -race ./provision/ -run 'TestFileStoreUserByID|TestNewAuthPSK' -v
/home/goodvin/.local/go/bin/go vet ./provision/
```
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/provision/store.go core/provision/store_test.go core/provision/provision.go core/provision/provision_test.go
git commit -m "feat(provision): UserByID + NewAuthPSK for the server enroll handler

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Multiplexed server rewrite (device path + enroll handler + sweep)

**Files:** Rewrite `core/server/server.go`; update `core/server/server_test.go` and `core/server/e2e_test.go`.

This replaces the per-client-device server. The gate→branch→data-path pipeline runs over one `MuxEngine`. Both the device handler and the enrollment handler are implemented (the enrollment exchange uses the merged `core/enroll` helpers). The `notifyTransport` (in `core/server/transport.go`) is unchanged and reused.

- [ ] **Step 1: Replace `core/server/server.go` with:**

```go
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
```

- [ ] **Step 2: Update `core/server/server_test.go`**

The server now needs a real TUN at construction. Replace the `New(...)` call (which used a `TunFactory`) and drop the `tun` import's factory usage. Replace the whole test body's server construction: after building `gate` and `sessions`, create a netstack TUN and build the server:
```go
	tunDev, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.100.0.1")}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	srv, err := New(gate, sessions, store, Config{}, tunDev)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
```
Update the imports of `core/server/server_test.go` to:
```go
import (
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/session"
	"golang.zx2c4.com/wireguard/tun/netstack"
)
```
(The `tun` import and the factory func are removed; the test no longer asserts "factory not called" — instead the gate closes the unauthenticated conn before any peer/registration, which the existing read-fails assertion already proves.) Keep the rest of the test (listen, dial, write junk, expect the conn closed, `srv.Close()`).

- [ ] **Step 3: Replace `core/server/e2e_test.go` with the multiplexed device-path e2e:**

```go
package server

import (
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/session"
	"github.com/g00dvin/gvpn/core/transport"
	"github.com/g00dvin/gvpn/core/wgengine"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// TestServerEndToEndTunnelHTTP provisions a device, then drives the full
// multiplexed pipeline: dial -> auth -> session bind -> WireGuard over the mux ->
// HTTP through the tunnel.
func TestServerEndToEndTunnelHTTP(t *testing.T) {
	serverWG, _ := wgengine.GeneratePrivateKey()
	serverTunIP := netip.MustParseAddr("10.100.0.1")
	clientTunIP := netip.MustParseAddr("10.100.0.2")

	reg := filepath.Join(t.TempDir(), "registry.json")
	c, err := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	store, err := provision.NewFileStore(reg, c)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if _, _, err := store.AddUser("e2e"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	bundle, mat, err := provision.Generate("e2e", clientTunIP.String(), provision.GenerateParams{
		ServerWGPublicKey: serverWG.PublicKey(),
		ServerEndpoint:    "vpn.example.com:443",
		ServerName:        "vpn.example.com",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := store.AddDevice(provision.Device{
		DeviceID: mat.DeviceID, User: mat.User, WGPublic: mat.WGPublic,
		TunnelIP: mat.TunnelIP, Source: "admin",
	}, mat.AuthPSK); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}

	// The server's single TUN + the netstack we run the HTTP service on.
	serverTun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverTunIP}, nil, 1420)
	if err != nil {
		t.Fatalf("server CreateNetTUN: %v", err)
	}
	srv, err := New(
		authgate.NewGate(store, nil),
		session.NewManager(time.Minute),
		store,
		Config{WGPrivateKey: serverWG, LogLevel: device.LogLevelSilent},
		serverTun,
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	// --- Client: dial, authenticate, bind a session, start WireGuard. ---
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
		Endpoint:      "server:0",
		Keepalive:     5,
	}, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("client wgengine: %v", err)
	}
	defer clientEng.Close()

	// --- HTTP service on the server's tunnel IP. ---
	httpLn, err := serverNet.ListenTCP(&net.TCPAddr{IP: serverTunIP.AsSlice(), Port: 80})
	if err != nil {
		t.Fatalf("netstack ListenTCP: %v", err)
	}
	httpSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello through the gvpn server")
	})}
	go httpSrv.Serve(httpLn)
	defer httpSrv.Close()

	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: clientNet.DialContext},
		Timeout:   2 * time.Second,
	}
	deadline := time.Now().Add(20 * time.Second)
	var body []byte
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get("http://10.100.0.1/")
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
}
```

- [ ] **Step 4: Run the server package**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test -race ./server/ -v 2>&1 | tail -30
/home/goodvin/.local/go/bin/go vet ./server/
```
Expected: PASS (the unauthenticated-conn test + the device-path e2e); vet clean. (The e2e drives a real WireGuard handshake over the mux; it may take a few seconds.)

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/server/server.go core/server/server_test.go core/server/e2e_test.go
git commit -m "feat(server): multiplexed server (MuxEngine) with kind-branched pipeline + enroll handler + sweep

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Self-enrollment end-to-end (no pre-provisioning)

**Files:** Create `core/server/enroll_e2e_test.go`.

This proves the dynamic-enrollment path: a device that is NOT pre-provisioned connects with the user's enroll PSK, completes the enroll exchange, receives its credentials, brings up its tunnel on the same connection, and reaches a service — and the server has persisted the new device in the registry.

- [ ] **Step 1: Write the test — create `core/server/enroll_e2e_test.go`:**

```go
package server

import (
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/enroll"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/session"
	"github.com/g00dvin/gvpn/core/transport"
	"github.com/g00dvin/gvpn/core/wgengine"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// TestServerSelfEnrollEndToEnd connects a brand-new (unprovisioned) device using
// only the user's enroll PSK, completes the in-band enrollment, then tunnels HTTP
// through the freshly granted credentials.
func TestServerSelfEnrollEndToEnd(t *testing.T) {
	serverWG, _ := wgengine.GeneratePrivateKey()
	serverTunIP := netip.MustParseAddr("10.100.0.1")

	reg := filepath.Join(t.TempDir(), "registry.json")
	c, err := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	store, err := provision.NewFileStore(reg, c)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	// Only a USER exists; no device is pre-provisioned.
	user, enrollPSK, err := store.AddUser("enrollee")
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	userID, _ := provision.ParseDeviceID(user.ID)

	serverTun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverTunIP}, nil, 1420)
	if err != nil {
		t.Fatalf("server CreateNetTUN: %v", err)
	}
	srv, err := New(
		authgate.NewGate(store, nil),
		session.NewManager(time.Minute),
		store,
		Config{WGPrivateKey: serverWG, Subnet: "10.100.0.0/24", LogLevel: device.LogLevelSilent},
		serverTun,
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	// --- New device: enroll AUTH -> enroll exchange -> learn credentials. ---
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := authgate.WriteEnrollAuth(conn, enrollPSK, userID); err != nil {
		t.Fatalf("WriteEnrollAuth: %v", err)
	}
	clientPriv, _ := wgengine.GeneratePrivateKey()
	resp, err := enroll.Exchange(conn, [32]byte(clientPriv.PublicKey()))
	if err != nil {
		t.Fatalf("enroll.Exchange: %v", err)
	}
	if resp.TunnelIP != "10.100.0.2" || len(resp.DevicePSK) == 0 {
		t.Fatalf("enroll response = %+v, want tunnel 10.100.0.2 and a psk", resp)
	}

	// Server persisted the new device.
	if _, ok := store.Device(resp.DeviceID); !ok {
		t.Fatal("server did not persist the enrolled device")
	}
	if n := store.DeviceCount("enrollee"); n != 1 {
		t.Fatalf("device count = %d, want 1", n)
	}

	// --- Bring up the tunnel on the same connection using the granted IP. ---
	clientTunIP := netip.MustParseAddr(resp.TunnelIP)
	clientTun, clientNet, err := netstack.CreateNetTUN([]netip.Addr{clientTunIP}, nil, 1420)
	if err != nil {
		t.Fatalf("client CreateNetTUN: %v", err)
	}
	clientEng, err := wgengine.New(clientTun, transport.NewStreamTransport(conn), wgengine.Config{
		PrivateKey:    clientPriv,
		PeerPublicKey: serverWG.PublicKey(),
		AllowedIPs:    []string{"0.0.0.0/0"},
		Endpoint:      "server:0",
		Keepalive:     5,
	}, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("client wgengine: %v", err)
	}
	defer clientEng.Close()

	httpLn, err := serverNet.ListenTCP(&net.TCPAddr{IP: serverTunIP.AsSlice(), Port: 80})
	if err != nil {
		t.Fatalf("netstack ListenTCP: %v", err)
	}
	httpSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "enrolled and tunneling")
	})}
	go httpSrv.Serve(httpLn)
	defer httpSrv.Close()

	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: clientNet.DialContext},
		Timeout:   2 * time.Second,
	}
	deadline := time.Now().Add(20 * time.Second)
	var body []byte
	for time.Now().Before(deadline) {
		r, err := httpClient.Get("http://10.100.0.1/")
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		body, _ = io.ReadAll(r.Body)
		r.Body.Close()
		break
	}
	if string(body) != "enrolled and tunneling" {
		t.Fatalf("post-enroll tunnel body = %q, want the greeting", body)
	}
}

// TestServerEnrollClosedRejected confirms a user with enrollment closed cannot
// enroll a device (the connection is dropped, no device is created).
func TestServerEnrollClosedRejected(t *testing.T) {
	serverWG, _ := wgengine.GeneratePrivateKey()
	reg := filepath.Join(t.TempDir(), "registry.json")
	c, _ := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	store, err := provision.NewFileStore(reg, c)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	user, enrollPSK, err := store.AddUser("closed")
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	// Close enrollment for this user by removing and re-adding is not exposed;
	// instead drive the registry directly: reload, flip EnrollOpen, save, reopen.
	rgy, _ := provision.LoadRegistry(reg)
	rgy.Users[0].EnrollOpen = false
	if err := provision.SaveRegistry(reg, rgy); err != nil {
		t.Fatalf("SaveRegistry: %v", err)
	}
	store, err = provision.NewFileStore(reg, c)
	if err != nil {
		t.Fatalf("reload store: %v", err)
	}
	userID, _ := provision.ParseDeviceID(user.ID)

	serverTun, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.100.0.1")}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	srv, err := New(authgate.NewGate(store, nil), session.NewManager(time.Minute), store,
		Config{WGPrivateKey: serverWG, LogLevel: device.LogLevelSilent}, serverTun)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := authgate.WriteEnrollAuth(conn, enrollPSK, userID); err != nil {
		t.Fatalf("WriteEnrollAuth: %v", err)
	}
	// The gate authenticates (the enroll PSK is valid), but the handler rejects
	// (EnrollOpen=false) and closes the connection before any reply.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 16)); err == nil {
		t.Fatal("server did not close the connection for a closed-enrollment user")
	}
	if n := store.DeviceCount("closed"); n != 0 {
		t.Fatalf("device count = %d, want 0 (no device created)", n)
	}
}
```

Note on `TestServerEnrollClosedRejected`: the client calls `WriteEnrollAuth` and then waits to read. Because the handler reads the enroll **request** frame only after passing guardrails, and here it rejects before reading, the server closes the connection without reading the request — the client's blocked `Read` returns an error, which is the assertion. The client does not send an enroll request frame in this test (it only writes the AUTH frame, then reads), which is sufficient to observe the closed connection.

- [ ] **Step 2: Run the enroll e2e**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test -race ./server/ -run 'TestServerSelfEnroll|TestServerEnrollClosed' -v 2>&1 | tail -30
```
Expected: both PASS. (The self-enroll test drives a real handshake; allow a few seconds.)

- [ ] **Step 3: Full server package under the race detector**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./server/ 2>&1 | tail -10`
Expected: PASS — unauthenticated-conn, device e2e, self-enroll e2e, closed-enroll — no races, no leaks.

- [ ] **Step 4: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/server/enroll_e2e_test.go
git commit -m "test(server): self-enroll-on-first-connect e2e + closed-enrollment rejection

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Final review + PR

**Files:** none (verification + PR only).

- [ ] **Step 1: Whole-module verification**

```bash
cd /home/goodvin/git/gvpn/core
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test -race ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go build ./...
```
Expected: all PASS / clean.

- [ ] **Step 2: Confirm server stays cgo-free**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go list -deps ./server/ | grep -iE 'gosttls' || echo "OK: no gosttls/cgo in server graph"`
Expected: `OK` (netstack/gvisor is fine — it is the test TUN; what matters is no `gosttls`/cgo).

- [ ] **Step 3: Opus final code + security review** (controller dispatches a fresh Opus subagent)

Review focus: the pipeline branches on `res.Kind` BEFORE any session bind (no zero-DeviceID session created on the enroll path); enrollment guardrails are enforced (missing/Disabled/!EnrollOpen and DeviceCap) and every rejection closes the connection with no distinguishing response (probe-resistance); the enroll handler persists the device (encrypted, via AddDevice) AND adds the live peer AND replies, with correct ordering and no partial state on error; allocated IPs come from the current `UsedIPs` under the store's lock (no duplicate IP across concurrent enrollments — note `AddDevice` is serialized by the FileStore mutex but allocation+add is not atomic across the whole handler, assess the race window and whether it matters for phase 1); per-peer allowed-IP is the device's `/32` (not 0.0.0.0/0); connection ids start at 1 (0 reserved); `Close` ordering (close conns → wait handlers → engine Close → sweep stop) has no deadlock or goroutine leak, and is idempotent; `Serve`'s `wg.Add` under the lock cannot race `Close`'s `wg.Wait`; no secrets logged (device PSK, enroll PSK, master key, keys); `core/server` stays cgo-free; the device e2e and self-enroll e2e prove the data path. Note any data race (run `-race`), deadlock, secret leak, or guardrail bypass as Critical.

- [ ] **Step 4: Push and open PR** (trivial / `gh` — Haiku)

```bash
cd /home/goodvin/git/gvpn
git push -u origin feat/mux-server
gh pr create --base main --head feat/mux-server \
  --title "Multiplexed server + in-band enrollment handler" \
  --body "Rewrites core/server to the multiplexed wgengine.MuxEngine (one device, one TUN, many peers) and adds the in-band dynamic-enrollment handler — wiring together the Plan 10 enrollment primitives and the Plan 11 multiplexed engine.

- Server owns one MuxEngine on an injected tun.Device; New(...) now returns (*Server, error) and Config gains Subnet (drops ClientAllowedIP); the per-client TunFactory is gone.
- handle(conn): gate -> branch on res.Kind. Device path: session bind -> resolve registered pubkey + tunnel IP -> AddPeer(pub, ip/32) -> register into the mux. Enroll path: guardrails (user enabled, enrollment open, DeviceCap) -> read WG pubkey -> allocate IP + DeviceID, mint PSK, AddDevice (persist, encrypted) + AddPeer (live) -> reply -> register into the mux.
- Per-peer allowed-IP is the device's /32; connection ids start at 1 (0 reserved); session-sweep ticker reaps expired sessions; Close closes conns, waits handlers, shuts the engine.
- provision: + FileStore.UserByID, + NewAuthPSK.
- Tests (netstack + TCP loopback, -race): device-path tunnel HTTP; self-enroll-on-first-connect (no pre-provisioning, then tunnels) + closed-enrollment rejection.

Breaking (internal): server.New signature + Config; no external consumers yet (the gvpn-server binary is the next plan). cgo-free; whole module green under -race + cgo.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

---

## Self-Review

**Spec coverage (design §7, §9):** multiplexed `Server` over one `MuxEngine` (Task 2); kind-branched pipeline with enroll BEFORE session bind (Task 2, resolving the Plan 10 review carry-over); the full enrollment handler — guardrails, WG pubkey read, IP/DeviceID allocation, PSK mint, persist + live `AddPeer`, reply (Task 2); per-peer `/32`; session sweep (the Plan 8 review carry-over); provision `UserByID`/`NewAuthPSK` (Task 1); device e2e + self-enroll e2e + closed-enroll rejection (Tasks 2–3). The `gvpn-server` binary (server.yaml, real TUN, GOST-TLS listener, routing/NAT, gencert) and the admin UI remain later plans; this plan keeps `New` injectable so the binary just supplies a real TUN + GOST listener.

**Placeholder scan:** none — every step has complete code or an exact edit location. Task 1's two helpers have full bodies; Task 2 provides the entire `server.go`; the test files are complete. The `TestServerEnrollClosedRejected` flips `EnrollOpen` via `LoadRegistry`/`SaveRegistry` (public) then reloads the store, since there is no CLI/store method to close enrollment yet (that lands with the admin API) — documented inline.

**Type consistency:** `New(*authgate.Gate, *session.Manager, *provision.FileStore, Config, tun.Device) (*Server, error)`; `Config{WGPrivateKey wgengine.Key; Subnet string; LogLevel int}`; handlers `handleDevice([16]byte, net.Conn)` / `handleEnroll([16]byte, net.Conn)` / `runDataPath(net.Conn)` / `track(net.Conn)(uint64,bool)` / `untrack(uint64)`. Uses merged APIs: `authgate.KindEnroll`, `Result.Kind`/`Result.UserID`/`Result.DeviceID`/`Result.Conn`; `enroll.ReadRequest(net.Conn)(enroll.Request,error)`, `enroll.WriteResponse(net.Conn, enroll.Response)`, `enroll.Request.WGPublic [32]byte`, `enroll.Response{DeviceID [16]byte, TunnelIP string, DevicePSK []byte}`, `enroll.Exchange(net.Conn,[32]byte)(enroll.Response,error)`, `authgate.WriteEnrollAuth`; `wgengine.NewMuxEngine`, `MuxEngine.AddPeer(Key,string)`, `Register(uint64, transport.PacketTransport)`, `Deregister(uint64)`, `Close`; `wgengine.Key(req.WGPublic)` and `[32]byte(key)` conversions (both 32-byte arrays); `[16]byte(provision.DeviceID)` conversion; `provision.FileStore.{Device,WGPublicKey,UserByID,DeviceCount,UsedIPs,AddDevice}`, `provision.AllocateIP`, `provision.NewDeviceID`, `provision.NewAuthPSK`. The unchanged `notifyTransport` (transport.go) is reused. Server tests use the new `New` signature.
