# Multiplexed WireGuard Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Per-task model assignment (standing rule):** **Sonnet** subagent implements each code task; **Opus** (controller) manages tasks and reviews each diff, and dispatches a fresh **Opus** subagent for the final review; **Haiku** subagent does the `gh` push + PR.

**Goal:** Add a multiplexed WireGuard engine to `core/wgengine` — ONE `wireguard-go` device + ONE TUN serving MANY connections (peers) — via a new `MuxBind` (per-connection reader goroutines fan into one receive channel, each packet tagged with its connection id; outbound packets route back by endpoint id) and a `MuxEngine` wrapper (incremental `AddPeer`/`RemovePeer`, `Register`/`Deregister`, `Close`). This replaces the per-client-device model's scaling limit at the engine layer.

**Architecture:** `muxEndpoint{id uint64}` implements `conn.Endpoint`; the id names the *connection* a packet arrived on, so returning it from the receive func lets wireguard-go learn (and, on reconnect, re-point) which connection reaches each peer. `MuxBind` keeps an `id → transport` map; `Register(id, pt)` starts a reader goroutine that fans frames into a shared `recv` channel tagged `muxEndpoint{id}`; the single receive func drains that channel; `Send(bufs, ep)` routes to the transport named by `ep.id` (unknown id → dropped, peer is mid-reconnect). `MuxEngine` wraps one `device.Device` on one injected `tun.Device`, sets only `private_key`, and adds peers incrementally via `IpcSet` so the WG session survives disconnects. Pure Go; cgo-free; TUN injected (netstack in tests, real kernel TUN later).

**Tech Stack:** Go 1.24, `golang.zx2c4.com/wireguard` (already pinned), stdlib. Toolchain `/home/goodvin/.local/go/bin/go`. Module `github.com/g00dvin/gvpn/core`.

**Design reference:** `docs/superpowers/specs/2026-06-16-user-identity-enrollment-admin-design.md` §9 (multiplexed server data path). **Scope note:** this plan delivers ONLY the engine layer. The `core/server` rewrite to use `MuxEngine` and the in-band enrollment handler are the *next* plan (they consume this one plus the Plan 10 enrollment primitives).

---

## Conventions

- Toolchain: `/home/goodvin/.local/go/bin/go`. Run with `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./wgengine/`.
- Branch `feat/mux-wgengine` off `main` (already created; this plan doc is committed there).
- Commits end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- `.gitignore` already covers stray binaries / `go.work.sum`. Only `git add` the files each task names.
- **Additive, non-breaking:** the existing single-conn `Bind`/`Engine` are UNCHANGED (the current per-client `core/server` keeps using them until the next plan). `MuxBind`/`MuxEngine` are new siblings.

## Decisions locked for this plan

- **Endpoint identity:** `muxEndpoint{id uint64}`; the id is assigned by the caller (the future server uses a monotonic counter per accepted connection). `DstToBytes`/`DstToString` encode the id so endpoints are distinct and debuggable.
- **Receive path:** one shared buffered channel (`conn.IdealBatchSize`), one receive func (matches the single-conn `Bind` shape); concurrency comes from the per-connection reader goroutines. `BatchSize() == 1`.
- **Send routing:** `Send` type-asserts `muxEndpoint`, looks up the transport by id under an `RWMutex`; unknown id or non-`muxEndpoint` → drop (return nil). No per-conn send mutex needed: `transport.StreamTransport.WritePacket` already serializes writes internally.
- **Reader lifecycle:** `Register` starts a reader (tracked by a `WaitGroup`); a reader exits when its transport errors (conn closed by the owner), when `Deregister(id)` closes its per-conn `stop` (releasing a reader blocked on the channel send), or when `Shutdown` closes the global `dead`. `Shutdown` (called by `MuxEngine.Close`) closes every still-registered transport to unblock readers parked in `ReadPacket`, then waits for all readers — so `Close` never leaks goroutines even if the caller hasn't closed the conns.
- **Peer persistence:** `AddPeer` is incremental `IpcSet` (`public_key` + `replace_allowed_ips=true` + `allowed_ip`); peers are kept across `Deregister`/`Register` so the WG session resumes on reconnect. `RemovePeer` uses `public_key` + `remove=true`.
- **`MuxEngine.Close`** does NOT own the registered connections (the future server does); `Shutdown` closes them only to unblock readers during teardown.

## File structure

```
core/wgengine/muxbind.go        muxEndpoint, MuxBind (Register/Deregister/Open/Close/Send/Shutdown/...)  (CREATE)
core/wgengine/muxbind_test.go   MuxBind unit tests with fake transports                                  (CREATE)
core/wgengine/muxengine.go      MuxEngine (NewMuxEngine/AddPeer/RemovePeer/Register/Deregister/Close)     (CREATE)
core/wgengine/muxengine_test.go MuxEngine construction/AddPeer/RemovePeer/Close unit test                 (CREATE)
core/wgengine/mux_e2e_test.go   two-client concurrent tunnel + reconnect-resumes, over netstack          (CREATE)
```

---

## Task 1: MuxBind (multiplexing conn.Bind)

**Files:** Create `core/wgengine/muxbind.go`, `core/wgengine/muxbind_test.go`.

The existing `bind_test.go` defines a `fakePT` in-memory `PacketTransport` (with exported-enough fields `in`/`out`/`Close`). The new tests reuse that type (same package), so do NOT redefine it.

- [ ] **Step 1: Write the failing tests — create `core/wgengine/muxbind_test.go`:**

```go
package wgengine

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// drainOne pulls a single packet from the bind's receive func, returning the
// payload and the endpoint id it was tagged with.
func drainOne(t *testing.T, fn conn.ReceiveFunc) ([]byte, uint64) {
	t.Helper()
	packets := [][]byte{make([]byte, 1500)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := fn(packets, sizes, eps)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if n != 1 {
		t.Fatalf("receive n = %d, want 1", n)
	}
	me, ok := eps[0].(muxEndpoint)
	if !ok {
		t.Fatalf("endpoint type = %T, want muxEndpoint", eps[0])
	}
	return append([]byte(nil), packets[0][:sizes[0]]...), me.id
}

func TestMuxBindFansInTaggedByConn(t *testing.T) {
	b := NewMuxBind()
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	pt1, pt2 := newFakePT(), newFakePT()
	b.Register(1, pt1)
	b.Register(2, pt2)

	pt1.in <- []byte("from-conn-1")
	pkt, id := drainOne(t, fns[0])
	if string(pkt) != "from-conn-1" || id != 1 {
		t.Fatalf("got (%q,%d), want (from-conn-1,1)", pkt, id)
	}
	pt2.in <- []byte("from-conn-2")
	pkt, id = drainOne(t, fns[0])
	if string(pkt) != "from-conn-2" || id != 2 {
		t.Fatalf("got (%q,%d), want (from-conn-2,2)", pkt, id)
	}
}

func TestMuxBindSendRoutesByEndpointID(t *testing.T) {
	b := NewMuxBind()
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	pt1, pt2 := newFakePT(), newFakePT()
	b.Register(1, pt1)
	b.Register(2, pt2)

	if err := b.Send([][]byte{[]byte("to-2")}, muxEndpoint{id: 2}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case got := <-pt2.out:
		if !bytes.Equal(got, []byte("to-2")) {
			t.Fatalf("conn 2 got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("nothing written to conn 2")
	}
	select {
	case stray := <-pt1.out:
		t.Fatalf("conn 1 unexpectedly received %q", stray)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestMuxBindSendUnknownEndpointDropped(t *testing.T) {
	b := NewMuxBind()
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()
	// No conn registered for id 99: Send must not error (peer is mid-reconnect).
	if err := b.Send([][]byte{[]byte("x")}, muxEndpoint{id: 99}); err != nil {
		t.Fatalf("Send to unknown id = %v, want nil (dropped)", err)
	}
}

func TestMuxBindSendCopies(t *testing.T) {
	b := NewMuxBind()
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()
	pt := newFakePT()
	b.Register(1, pt)
	buf := []byte("mutate-me")
	if err := b.Send([][]byte{buf}, muxEndpoint{id: 1}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	for i := range buf {
		buf[i] = 0
	}
	select {
	case got := <-pt.out:
		if string(got) != "mutate-me" {
			t.Fatalf("Send did not copy: got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("nothing written")
	}
}

func TestMuxBindDeregisterStopsRouting(t *testing.T) {
	b := NewMuxBind()
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()
	pt := newFakePT()
	b.Register(1, pt)
	b.Deregister(1)
	// After Deregister, the id is unknown, so Send drops (no error).
	if err := b.Send([][]byte{[]byte("x")}, muxEndpoint{id: 1}); err != nil {
		t.Fatalf("Send after Deregister = %v, want nil", err)
	}
	pt.Close()
}

func TestMuxBindCloseUnblocksReceive(t *testing.T) {
	b := NewMuxBind()
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	errc := make(chan error, 1)
	go func() {
		_, e := fns[0]([][]byte{make([]byte, 1500)}, make([]int, 1), make([]conn.Endpoint, 1))
		errc <- e
	}()
	time.Sleep(20 * time.Millisecond)
	b.Close()
	select {
	case e := <-errc:
		if !errors.Is(e, net.ErrClosed) {
			t.Fatalf("receive after Close = %v, want net.ErrClosed", e)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock the receive func")
	}
}

func TestMuxBindShutdownReleasesReaders(t *testing.T) {
	b := NewMuxBind()
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	pt := newFakePT()
	b.Register(1, pt) // reader will park in ReadPacket (no input)
	b.Close()
	done := make(chan struct{})
	go func() { b.Shutdown(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return (reader leak)")
	}
}

func TestMuxBindStaticContract(t *testing.T) {
	b := NewMuxBind()
	if b.BatchSize() != 1 {
		t.Fatalf("BatchSize = %d, want 1", b.BatchSize())
	}
	if err := b.SetMark(0); err != nil {
		t.Fatalf("SetMark: %v", err)
	}
	if ep, err := b.ParseEndpoint("anything"); err != nil || ep == nil {
		t.Fatalf("ParseEndpoint: ep=%v err=%v", ep, err)
	}
}
```

- [ ] **Step 2: Run to confirm FAIL**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./wgengine/ -run TestMuxBind -v 2>&1 | tail -20`
Expected: build error — `undefined: NewMuxBind` / `muxEndpoint`.

- [ ] **Step 3: Create `core/wgengine/muxbind.go`:**

```go
package wgengine

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/g00dvin/gvpn/core/transport"
	"golang.zx2c4.com/wireguard/conn"
)

// muxEndpoint identifies the connection a packet arrived on. wireguard-go treats
// it as the peer's endpoint, so returning it from the receive func lets the
// device learn — and, on reconnect, re-point — which connection reaches a peer.
type muxEndpoint struct{ id uint64 }

func (muxEndpoint) ClearSrc()             {}
func (muxEndpoint) SrcToString() string   { return "" }
func (e muxEndpoint) DstToString() string { return fmt.Sprintf("gvpn-mux:%d", e.id) }
func (e muxEndpoint) DstToBytes() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, e.id)
	return b
}
func (muxEndpoint) DstIP() netip.Addr { return netip.Addr{} }
func (muxEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

// muxItem is one received packet tagged with its origin connection id.
type muxItem struct {
	pkt []byte
	ep  muxEndpoint
}

// muxConn tracks one registered connection's transport and reader stop signal.
type muxConn struct {
	pt   transport.PacketTransport
	stop chan struct{}
	once sync.Once
}

// MuxBind is a conn.Bind for ONE wireguard-go device fed by MANY connections.
// Each registered connection runs a reader goroutine that fans frames into a
// shared receive channel tagged with the connection id; Send routes an outbound
// packet back to the connection named by its endpoint id.
type MuxBind struct {
	mu   sync.Mutex
	open bool
	done chan struct{} // current Open generation; closed by Close
	recv chan muxItem

	connsMu sync.RWMutex
	conns   map[uint64]*muxConn

	wg       sync.WaitGroup
	dead     chan struct{} // closed by Shutdown; releases readers blocked on recv
	deadOnce sync.Once
}

var _ conn.Bind = (*MuxBind)(nil)

// NewMuxBind builds an empty MuxBind. Register connections after Open.
func NewMuxBind() *MuxBind {
	return &MuxBind{
		recv:  make(chan muxItem, conn.IdealBatchSize),
		conns: make(map[uint64]*muxConn),
		dead:  make(chan struct{}),
	}
}

// Open returns a single receive function draining the shared channel. actualPort
// is 0 (the transport is not UDP). wireguard may Close+Open during reconfig; each
// Open starts a fresh receive generation.
func (b *MuxBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.done = make(chan struct{})
	b.open = true
	done := b.done

	fn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case it := <-b.recv:
			sizes[0] = copy(packets[0], it.pkt)
			eps[0] = it.ep
			return 1, nil
		case <-done:
			return 0, net.ErrClosed
		}
	}
	return []conn.ReceiveFunc{fn}, 0, nil
}

// Close ends the current receive generation. It does not stop readers or touch
// the connections.
func (b *MuxBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.open = false
	if b.done != nil {
		select {
		case <-b.done:
		default:
			close(b.done)
		}
	}
	return nil
}

// Register adds connection id backed by pt and starts its reader goroutine. The
// reader exits when pt errors (owner closed the conn), when Deregister(id) is
// called, or when Shutdown closes the bind.
func (b *MuxBind) Register(id uint64, pt transport.PacketTransport) {
	mc := &muxConn{pt: pt, stop: make(chan struct{})}
	b.connsMu.Lock()
	b.conns[id] = mc
	b.connsMu.Unlock()

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for {
			p, err := pt.ReadPacket()
			if err != nil {
				return
			}
			select {
			case b.recv <- muxItem{pkt: p, ep: muxEndpoint{id: id}}:
			case <-mc.stop:
				return
			case <-b.dead:
				return
			}
		}
	}()
}

// Deregister removes connection id from the routing table and signals its reader
// to stop. A reader parked in ReadPacket exits when the owner closes the conn.
func (b *MuxBind) Deregister(id uint64) {
	b.connsMu.Lock()
	mc, ok := b.conns[id]
	if ok {
		delete(b.conns, id)
	}
	b.connsMu.Unlock()
	if ok {
		mc.once.Do(func() { close(mc.stop) })
	}
}

// Send routes each packet to the transport named by ep.id. wireguard reuses bufs
// after Send, so each packet is copied first. An unknown id or non-mux endpoint
// is dropped (the peer's endpoint is stale until it reconnects).
func (b *MuxBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	open := b.open
	b.mu.Unlock()
	if !open {
		return net.ErrClosed
	}
	me, ok := ep.(muxEndpoint)
	if !ok {
		return nil
	}
	b.connsMu.RLock()
	mc, ok := b.conns[me.id]
	b.connsMu.RUnlock()
	if !ok {
		return nil
	}
	for _, buf := range bufs {
		if len(buf) == 0 {
			continue
		}
		pkt := make([]byte, len(buf))
		copy(pkt, buf)
		if err := mc.pt.WritePacket(pkt); err != nil {
			return err
		}
	}
	return nil
}

// Shutdown releases all reader goroutines and waits for them to exit. It closes
// every still-registered transport to unblock readers parked in ReadPacket, so
// it never hangs even if the owner has not closed the conns. Called by
// MuxEngine.Close after the device is closed.
func (b *MuxBind) Shutdown() {
	b.deadOnce.Do(func() { close(b.dead) })
	b.connsMu.Lock()
	for id, mc := range b.conns {
		mc.pt.Close()
		delete(b.conns, id)
	}
	b.connsMu.Unlock()
	b.wg.Wait()
}

// ParseEndpoint returns a zero-id mux endpoint regardless of s. The server never
// configures a static endpoint= (it does not initiate), so this is unused in
// practice; a zero id is unknown to Send and harmlessly drops.
func (b *MuxBind) ParseEndpoint(s string) (conn.Endpoint, error) { return muxEndpoint{}, nil }

// SetMark is a no-op: there is no OS socket to mark.
func (b *MuxBind) SetMark(mark uint32) error { return nil }

// BatchSize is 1: a framed stream delivers one packet per read.
func (b *MuxBind) BatchSize() int { return 1 }
```

- [ ] **Step 4: Run to confirm PASS**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test -race ./wgengine/ -run TestMuxBind -v 2>&1 | tail -40
/home/goodvin/.local/go/bin/go vet ./wgengine/
```
Expected: PASS / clean (the existing single-conn Bind tests are untouched and still pass).

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/wgengine/muxbind.go core/wgengine/muxbind_test.go
git commit -m "feat(wgengine): MuxBind — one device, many connections

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: MuxEngine (one device, many peers)

**Files:** Create `core/wgengine/muxengine.go`, `core/wgengine/muxengine_test.go`.

- [ ] **Step 1: Write the failing test — create `core/wgengine/muxengine_test.go`:**

```go
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
```

- [ ] **Step 2: Run to confirm FAIL**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./wgengine/ -run TestMuxEngine -v 2>&1 | tail -20`
Expected: build error — `undefined: NewMuxEngine`.

- [ ] **Step 3: Create `core/wgengine/muxengine.go`:**

```go
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
// during teardown.
func (e *MuxEngine) Close() error {
	e.dev.Close()     // ends the bind's receive funcs
	e.bind.Shutdown() // releases readers, closes registered transports
	return nil
}
```

- [ ] **Step 4: Run to confirm PASS**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test -race ./wgengine/ -run TestMuxEngine -v 2>&1 | tail -30
/home/goodvin/.local/go/bin/go vet ./wgengine/
```
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/wgengine/muxengine.go core/wgengine/muxengine_test.go
git commit -m "feat(wgengine): MuxEngine — incremental peers over MuxBind

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Multiplexed end-to-end (two clients + reconnect)

**Files:** Create `core/wgengine/mux_e2e_test.go`.

These tests prove the real WireGuard handshake + data path through `MuxEngine`: one server device with one TUN serves two client peers over two connections concurrently, and a peer's tunnel resumes after it reconnects on a new connection. They mirror the existing `e2e_test.go` (netstack TUNs + TCP loopback transports), so reuse those patterns.

- [ ] **Step 1: Write the test — create `core/wgengine/mux_e2e_test.go`:**

```go
package wgengine

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/transport"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// loopbackPair returns the two ends of a TCP loopback connection.
func loopbackPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type accepted struct {
		c   net.Conn
		err error
	}
	ac := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		ac <- accepted{c, err}
	}()
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	a := <-ac
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}
	return a.c, dialed // server side, client side
}

// startClient brings up a single-conn client Engine on its own netstack TUN that
// initiates to the server. It returns the client's netstack (for dialing) and
// the Engine.
func startClient(t *testing.T, clientPriv, serverPub Key, clientIP netip.Addr, clientConn net.Conn) (*netstack.Net, *Engine) {
	t.Helper()
	clientTun, clientNet, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1420)
	if err != nil {
		t.Fatalf("client CreateNetTUN: %v", err)
	}
	eng, err := New(clientTun, transport.NewStreamTransport(clientConn), Config{
		PrivateKey:    clientPriv,
		PeerPublicKey: serverPub,
		AllowedIPs:    []string{"0.0.0.0/0"},
		Endpoint:      "gvpn-peer:0",
		Keepalive:     5,
	}, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	return clientNet, eng
}

// getThrough retries an HTTP GET to the server over the client netstack until
// the handshake completes or the deadline passes.
func getThrough(t *testing.T, clientNet *netstack.Net, serverIP netip.Addr) string {
	t.Helper()
	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: clientNet.DialContext},
		Timeout:   2 * time.Second,
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get(fmt.Sprintf("http://%s/", serverIP))
		if err != nil {
			time.Sleep(150 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return string(body)
	}
	return ""
}

func TestMuxEngineTwoClientsConcurrent(t *testing.T) {
	serverPriv, _ := GeneratePrivateKey()
	clientAPriv, _ := GeneratePrivateKey()
	clientBPriv, _ := GeneratePrivateKey()
	serverIP := netip.MustParseAddr("10.100.0.1")
	clientAIP := netip.MustParseAddr("10.100.0.2")
	clientBIP := netip.MustParseAddr("10.100.0.3")

	serverTun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1420)
	if err != nil {
		t.Fatalf("server CreateNetTUN: %v", err)
	}
	serverEng, err := NewMuxEngine(serverTun, serverPriv, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("NewMuxEngine: %v", err)
	}
	defer serverEng.Close()
	if err := serverEng.AddPeer(clientAPriv.PublicKey(), clientAIP.String()+"/32"); err != nil {
		t.Fatalf("AddPeer A: %v", err)
	}
	if err := serverEng.AddPeer(clientBPriv.PublicKey(), clientBIP.String()+"/32"); err != nil {
		t.Fatalf("AddPeer B: %v", err)
	}

	srvSideA, cliSideA := loopbackPair(t)
	srvSideB, cliSideB := loopbackPair(t)
	serverEng.Register(1, transport.NewStreamTransport(srvSideA))
	serverEng.Register(2, transport.NewStreamTransport(srvSideB))

	clientANet, clientAEng := startClient(t, clientAPriv, serverPriv.PublicKey(), clientAIP, cliSideA)
	defer clientAEng.Close()
	clientBNet, clientBEng := startClient(t, clientBPriv, serverPriv.PublicKey(), clientBIP, cliSideB)
	defer clientBEng.Close()

	// HTTP server on the server netstack.
	httpLn, err := serverNet.ListenTCP(&net.TCPAddr{IP: serverIP.AsSlice(), Port: 80})
	if err != nil {
		t.Fatalf("netstack ListenTCP: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from "+r.Host)
	})}
	go srv.Serve(httpLn)
	defer srv.Close()

	if got := getThrough(t, clientANet, serverIP); got == "" {
		t.Fatal("client A could not reach the server through the mux tunnel")
	}
	if got := getThrough(t, clientBNet, serverIP); got == "" {
		t.Fatal("client B could not reach the server through the mux tunnel")
	}
}

func TestMuxEngineReconnectResumes(t *testing.T) {
	serverPriv, _ := GeneratePrivateKey()
	clientPriv, _ := GeneratePrivateKey()
	serverIP := netip.MustParseAddr("10.100.0.1")
	clientIP := netip.MustParseAddr("10.100.0.2")

	serverTun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1420)
	if err != nil {
		t.Fatalf("server CreateNetTUN: %v", err)
	}
	serverEng, err := NewMuxEngine(serverTun, serverPriv, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("NewMuxEngine: %v", err)
	}
	defer serverEng.Close()
	if err := serverEng.AddPeer(clientPriv.PublicKey(), clientIP.String()+"/32"); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	httpLn, err := serverNet.ListenTCP(&net.TCPAddr{IP: serverIP.AsSlice(), Port: 80})
	if err != nil {
		t.Fatalf("netstack ListenTCP: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})}
	go srv.Serve(httpLn)
	defer srv.Close()

	// First connection on id 1.
	srvSide1, cliSide1 := loopbackPair(t)
	serverEng.Register(1, transport.NewStreamTransport(srvSide1))
	clientNet1, clientEng1 := startClient(t, clientPriv, serverPriv.PublicKey(), clientIP, cliSide1)
	if got := getThrough(t, clientNet1, serverIP); got != "ok" {
		t.Fatalf("first connect: tunnel body = %q", got)
	}

	// "Reconnect": drop conn 1, register a fresh conn 2 for the same peer.
	clientEng1.Close()
	serverEng.Deregister(1)
	srvSide2, cliSide2 := loopbackPair(t)
	serverEng.Register(2, transport.NewStreamTransport(srvSide2))
	clientNet2, clientEng2 := startClient(t, clientPriv, serverPriv.PublicKey(), clientIP, cliSide2)
	defer clientEng2.Close()

	// The peer (kept across Deregister) resumes on the new connection: the server
	// re-points its endpoint to muxEndpoint{2} on the next valid packet.
	if got := getThrough(t, clientNet2, serverIP); got != "ok" {
		t.Fatalf("after reconnect: tunnel body = %q (endpoint did not re-point)", got)
	}
}
```

- [ ] **Step 2: Run the tests**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./wgengine/ -run TestMuxEngineTwoClients -v 2>&1 | tail -30`
Then: `/home/goodvin/.local/go/bin/go test ./wgengine/ -run TestMuxEngineReconnect -v 2>&1 | tail -30`
Expected: both PASS. (If a run is flaky under heavy load, re-run once; the 15s handshake retry budget should be ample.)

- [ ] **Step 3: Full wgengine suite under the race detector**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race -count=2 ./wgengine/ 2>&1 | tail -20`
Expected: PASS (single-conn Bind/Engine tests + all mux tests), no data races, no goroutine-leak hangs.

- [ ] **Step 4: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/wgengine/mux_e2e_test.go
git commit -m "test(wgengine): multiplexed e2e — two clients + reconnect resume

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

- [ ] **Step 2: Confirm wgengine stays cgo-free**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go list -deps ./wgengine/ | grep -iE 'gosttls|cgo' || echo "OK: no cgo in wgengine graph"`
Expected: `OK` (netstack/gvisor is fine here — it is the test TUN; what matters is no `gosttls`/cgo).

- [ ] **Step 3: Opus final code + security review** (controller dispatches a fresh Opus subagent)

Review focus: MuxBind reader lifecycle (no goroutine leak on Deregister/Close/Shutdown; `wg.Wait` cannot hang because Shutdown closes registered transports); the receive path tags every packet with the correct connection id and Send routes strictly by id (no cross-talk); unknown/stale endpoint id is dropped, not errored (roaming correctness); Send copies bufs (wireguard reuse) and relies on StreamTransport's internal write serialization; concurrency correctness under `-race` (the `connsMu` covers the map, the `mu` covers open/done, no lock-ordering inversion); `AddPeer` is incremental + idempotent and peers survive Deregister/Register (reconnect resume proven by the e2e); `RemovePeer` revokes; the single-conn `Bind`/`Engine` are untouched; no secrets logged; wgengine stays cgo-free. Note any data race, deadlock, or endpoint mis-routing as Critical.

- [ ] **Step 4: Push and open PR** (trivial / `gh` — Haiku)

```bash
cd /home/goodvin/git/gvpn
git push -u origin feat/mux-wgengine
gh pr create --base main --head feat/mux-wgengine \
  --title "Multiplexed WireGuard engine: MuxBind + MuxEngine (one device, many peers)" \
  --body "Adds a multiplexed WireGuard engine to core/wgengine: ONE wireguard-go device + ONE TUN serving MANY connections/peers. Engine layer only — the core/server rewrite and the in-band enrollment handler are the next plan.

- muxEndpoint{id} implements conn.Endpoint; the id names the connection a packet arrived on, so wireguard learns/re-points each peer's endpoint.
- MuxBind: Register(id,pt) runs a per-conn reader fanning frames into one shared recv channel tagged by id; Open returns one receive func draining it; Send routes by ep.id (unknown id dropped = peer mid-reconnect); Deregister stops a reader; Shutdown closes registered transports + waits (no goroutine leak).
- MuxEngine: NewMuxEngine(tun, privKey, logLevel) sets only private_key; AddPeer (incremental, idempotent, replace_allowed_ips) keeps peers across disconnects; RemovePeer revokes; Register/Deregister delegate; Close shuts the device + readers.
- Tests (netstack + TCP loopback, -race): MuxBind fan-in/routing/drop/deregister/shutdown units; two-client concurrent tunnel; reconnect-resumes (peer survives Deregister/Register, endpoint re-points to the new conn).

Additive and non-breaking: the existing single-conn Bind/Engine are untouched (the current per-client server keeps using them until the next plan). cgo-free; whole module green under -race + cgo.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

---

## Self-Review

**Spec coverage (design §9):** `muxEndpoint{id}` (Task 1), `MuxBind.Register`/`Deregister`/`Open`/`Send` fan-in + routing (Task 1), `MuxEngine` with `NewMuxEngine`/`AddPeer`/`RemovePeer`/`Register`/`Deregister`/`Close` (Task 2), and the roaming/resume property exercised by the reconnect e2e (Task 3). The two items §9 assigns to `core/server` — the multiplexed `Server` rewrite (replacing the per-client one, keeping `notifyTransport`, allocating connIDs, the `<-Done()`/`Deregister` loop) and the enrollment handler — are explicitly the NEXT plan; they consume this engine plus the merged Plan 10 primitives. This plan deliberately leaves the single-conn `Bind`/`Engine` and `core/server` unchanged.

**Placeholder scan:** none — every step has complete code. `fakePT`/`newFakePT` are reused from the existing `bind_test.go` (same package), not redefined. The e2e helpers (`loopbackPair`, `startClient`, `getThrough`) are defined in `mux_e2e_test.go` and reused by both e2e tests.

**Type consistency:** `muxEndpoint{id uint64}` (conn.Endpoint); `NewMuxBind() *MuxBind`; `MuxBind.Open(uint16) ([]conn.ReceiveFunc, uint16, error)`, `Close() error`, `Register(uint64, transport.PacketTransport)`, `Deregister(uint64)`, `Send([][]byte, conn.Endpoint) error`, `Shutdown()`, `ParseEndpoint`/`SetMark`/`BatchSize`; `NewMuxEngine(tun.Device, Key, int) (*MuxEngine, error)`, `AddPeer(Key, string) error`, `RemovePeer(Key) error`, `Register(uint64, transport.PacketTransport)`, `Deregister(uint64)`, `Close() error`. `MuxBind` satisfies `conn.Bind` (compile-time assert `var _ conn.Bind = (*MuxBind)(nil)`). Uses the existing `Key`, `GeneratePrivateKey`, `transport.NewStreamTransport`, and `transport.StreamTransport`'s internally-serialized `WritePacket`.
