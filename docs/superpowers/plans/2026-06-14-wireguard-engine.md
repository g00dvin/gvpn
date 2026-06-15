# WireGuard Engine (wireguard-go over PacketTransport) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. This package adds the `wireguard-go` dependency but is itself pure Go (no cgo). The heavyweight `tun/netstack` (gVisor) import is **test-only** — keep it out of non-test files so the gomobile build stays lean.
>
> **Per-task model assignment (standing rule):**
> - **Sonnet** subagent — implements each code task (Tasks 1–4).
> - **Opus** (controller) — manages tasks, reviews each diff; dispatches a fresh **Opus** subagent for the final code + security review (Task 5).
> - **Haiku** subagent — `gh` push + PR (Task 5).

**Goal:** Embed `wireguard-go` and drive its outside traffic through our single connection-oriented `transport.PacketTransport` (GOST TLS + framing + reconnection) instead of UDP, so real IP traffic flows through the VPN. This is the WireGuard Engine component of the spec.

**Architecture:** A new pure-Go `core/wgengine` package. `Bind` implements `wireguard-go`'s `conn.Bind` over a `transport.PacketTransport`: a background goroutine converts the blocking `ReadPacket` into a channel the receive funcs select on; `Send` copies each packet (wireguard reuses its buffers) and calls `WritePacket`. `Engine` wraps a `device.Device` built on a caller-supplied `tun.Device` (a real TUN in production; `tun/netstack` in tests), applies the WireGuard UAPI config, and brings it up. Because the transport already addresses exactly one peer (one connection), endpoint addressing is a fixed placeholder. **Validated:** a spike proved this exact pattern — two userspace (`netstack`) wireguard-go devices completed a Noise handshake and exchanged HTTP over an in-process channel `conn.Bind`, against `wireguard-go v0.0.0-20260522210424-ecfc5a8d5446`.

**Tech Stack:** Go 1.24, `golang.zx2c4.com/wireguard@v0.0.0-20260522210424-ecfc5a8d5446` (`conn`, `device`, `tun`, and test-only `tun/netstack`), `golang.org/x/crypto/curve25519`. Builds on `core/transport` (`PacketTransport`, `NewStreamTransport`). Toolchain `/home/goodvin/.local/go/bin/go` (system `go` is 1.19, too old). No cgo.

**Design reference:** `spec.md` (WireGuard Engine ↔ `PacketTransport` coupling), `docs/superpowers/specs/2026-06-13-gvpn-transport-design.md` §3 (double-crypto), §7 (MTU ≈ 1420).

---

## Conventions

- Toolchain: `/home/goodvin/.local/go/bin/go`. Run package tests with:
  `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./wgengine/`
- Branch `feat/wireguard-engine` off `main` (already created). Work from `/home/goodvin/git/gvpn`.
- Commits end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Module path `github.com/g00dvin/gvpn/core`; import the transport as `github.com/g00dvin/gvpn/core/transport`.
- **Keep `tun/netstack` (and thus gVisor) out of non-`_test.go` files** — it must not enter the gomobile build.

## Pinned wireguard-go API (verified by spike, this exact version)

```go
// golang.zx2c4.com/wireguard/conn
type Bind interface {
    Open(port uint16) (fns []ReceiveFunc, actualPort uint16, err error)
    Close() error
    SetMark(mark uint32) error
    Send(bufs [][]byte, ep Endpoint) error
    ParseEndpoint(s string) (Endpoint, error)
    BatchSize() int
}
type ReceiveFunc func(packets [][]byte, sizes []int, eps []Endpoint) (n int, err error)
type Endpoint interface {
    ClearSrc(); SrcToString() string; DstToString() string
    DstToBytes() []byte; DstIP() netip.Addr; SrcIP() netip.Addr
}
const IdealBatchSize = 128

// golang.zx2c4.com/wireguard/device
func NewDevice(tunDevice tun.Device, bind conn.Bind, logger *Logger) *Device
func NewLogger(level int, prepend string) *Logger
const (LogLevelSilent = 0; LogLevelError = 1; LogLevelVerbose = 2)
func (*Device) IpcSet(uapiConf string) error   // WireGuard UAPI, hex keys, one key=value per line
func (*Device) Up() error
func (*Device) Close()

// golang.zx2c4.com/wireguard/tun/netstack  (TEST ONLY)
func CreateNetTUN(localAddresses, dnsServers []netip.Addr, mtu int) (tun.Device, *Net, error)
func (*Net) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error)
func (*Net) DialContext(ctx context.Context, network, address string) (net.Conn, error)
```

**Critical gotchas (from the spike) the implementer MUST honor:**
- In `Send`, **copy every packet** out of `bufs[i]` before `WritePacket` — wireguard reuses the buffer immediately after `Send` returns.
- In the receive func, **copy into `packets[0]`** (`sizes[0] = copy(packets[0], p)`); never replace the slice. Return `n=1`.
- `BatchSize()` returns **1** (framed stream, one packet per read).
- `Close()` must make the receive funcs return `net.ErrClosed`; the device blocks on close until they do.
- The client side MUST set `endpoint=` in its config to arm handshake initiation; the server leaves it empty. `ParseEndpoint` returns a fixed endpoint regardless of the string.
- Do **not** set `listen_port` in the UAPI (no UDP port); minimizes bind churn.

## File structure

```
core/wgengine/bind.go        Bind: conn.Bind over transport.PacketTransport (+ fixed endpoint)
core/wgengine/bind_test.go
core/wgengine/keys.go        Curve25519 Key type: GeneratePrivateKey, PublicKey, Hex
core/wgengine/keys_test.go
core/wgengine/engine.go      Config + Engine (device wiring, UAPI builder, New/Close)
core/wgengine/engine_test.go smoke test (build/up/close over a netstack tun)
core/wgengine/e2e_test.go    end-to-end: two engines over a StreamTransport pair + netstack
```

---

## Task 1: Bind adapter (conn.Bind over PacketTransport)

**Files:** Create `core/wgengine/bind.go`, `core/wgengine/bind_test.go`.

- [ ] **Step 1: Add the wireguard-go dependency**

Run: `cd /home/goodvin/git/gvpn/core && GOFLAGS=-mod=mod /home/goodvin/.local/go/bin/go get golang.zx2c4.com/wireguard@v0.0.0-20260522210424-ecfc5a8d5446`
Expected: it downloads and updates `core/go.mod` / `core/go.sum`.

- [ ] **Step 2: Write the failing test**

Create `core/wgengine/bind_test.go`:
```go
package wgengine

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// fakePT is an in-memory PacketTransport for testing the Bind.
type fakePT struct {
	in        chan []byte // ReadPacket source
	out       chan []byte // WritePacket sink
	closeOnce sync.Once
	closed    chan struct{}
}

func newFakePT() *fakePT {
	return &fakePT{in: make(chan []byte, 8), out: make(chan []byte, 8), closed: make(chan struct{})}
}
func (f *fakePT) ReadPacket() ([]byte, error) {
	select {
	case p := <-f.in:
		return p, nil
	case <-f.closed:
		return nil, net.ErrClosed
	}
}
func (f *fakePT) WritePacket(p []byte) error {
	select {
	case f.out <- p:
		return nil
	case <-f.closed:
		return net.ErrClosed
	}
}
func (f *fakePT) Close() error { f.closeOnce.Do(func() { close(f.closed) }); return nil }

func TestBindSendCopiesAndForwards(t *testing.T) {
	pt := newFakePT()
	b := NewBind(pt)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	pkt := []byte("wireguard-packet")
	if err := b.Send([][]byte{pkt}, peerEndpoint{}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// Mutating the caller's buffer after Send must not affect what was written.
	for i := range pkt {
		pkt[i] = 0
	}
	select {
	case got := <-pt.out:
		if !bytes.Equal(got, []byte("wireguard-packet")) {
			t.Fatalf("forwarded %q, want %q (Send must copy)", got, "wireguard-packet")
		}
	case <-time.After(time.Second):
		t.Fatal("nothing written to transport")
	}
}

func TestBindReceiveDeliversPacket(t *testing.T) {
	pt := newFakePT()
	b := NewBind(pt)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	pt.in <- []byte("incoming")
	packets := [][]byte{make([]byte, 1500)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := fns[0](packets, sizes, eps)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if n != 1 || string(packets[0][:sizes[0]]) != "incoming" {
		t.Fatalf("receive n=%d data=%q", n, packets[0][:sizes[0]])
	}
}

func TestBindCloseUnblocksReceive(t *testing.T) {
	pt := newFakePT()
	b := NewBind(pt)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	errc := make(chan error, 1)
	go func() {
		packets := [][]byte{make([]byte, 1500)}
		_, e := fns[0](packets, make([]int, 1), make([]conn.Endpoint, 1))
		errc <- e
	}()
	time.Sleep(20 * time.Millisecond) // let the receive func block
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

func TestBindReopenAfterClose(t *testing.T) {
	pt := newFakePT()
	b := NewBind(pt)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open 1: %v", err)
	}
	b.Close()
	fns, _, err := b.Open(0) // wireguard may Close+Open during (re)configuration
	if err != nil {
		t.Fatalf("Open 2: %v", err)
	}
	pt.in <- []byte("after-reopen")
	n, err := fns[0]([][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1))
	if err != nil || n != 1 {
		t.Fatalf("receive after reopen: n=%d err=%v", n, err)
	}
}

func TestBindStaticContract(t *testing.T) {
	b := NewBind(newFakePT())
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

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./wgengine/ -run TestBind -v`
Expected: FAIL — `undefined: NewBind`, `undefined: peerEndpoint`.

- [ ] **Step 4: Write the implementation**

Create `core/wgengine/bind.go`:
```go
// Package wgengine embeds wireguard-go and drives its outside traffic over a
// connection-oriented transport.PacketTransport (GOST TLS + framing) instead of
// UDP. Pure Go; the TUN device is supplied by the caller (real TUN in
// production, tun/netstack in tests).
package wgengine

import (
	"net"
	"net/netip"
	"sync"

	"github.com/g00dvin/gvpn/core/transport"
	"golang.zx2c4.com/wireguard/conn"
)

// peerEndpoint is the single fixed endpoint for our point-to-point bind. The
// transport already targets exactly one peer (one connection), so endpoint
// addressing is meaningless; we return this for every Send/Receive.
type peerEndpoint struct{}

func (peerEndpoint) ClearSrc()           {}
func (peerEndpoint) SrcToString() string { return "" }
func (peerEndpoint) DstToString() string { return "gvpn-transport" }
func (peerEndpoint) DstToBytes() []byte  { return []byte("gvpn") }
func (peerEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (peerEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// Bind adapts a transport.PacketTransport to wireguard-go's conn.Bind.
//
// Lifecycle: one Bind wraps one transport for the life of one device. Open may
// be called more than once (wireguard calls Close+Open when reconfiguring the
// bind); each Open starts a fresh receive generation. Bind.Close stops the
// current receive funcs (they return net.ErrClosed) but does NOT close the
// transport. The owner (Engine) calls stopReader() + transport.Close() to end
// the background reader.
type Bind struct {
	pt transport.PacketTransport

	mu   sync.Mutex
	open bool
	done chan struct{} // closed by Close; replaced on each Open

	recv     chan []byte // background reader -> receive funcs
	readerOn sync.Once
	dead     chan struct{} // closed by stopReader to release a blocked reader
	deadOnce sync.Once

	sendMu sync.Mutex // serializes WritePacket
}

var _ conn.Bind = (*Bind)(nil)

// NewBind wraps pt as a conn.Bind.
func NewBind(pt transport.PacketTransport) *Bind {
	return &Bind{
		pt:   pt,
		recv: make(chan []byte, conn.IdealBatchSize),
		dead: make(chan struct{}),
	}
}

// Open returns a single receive function backed by the transport. actualPort is
// 0 (the transport is not UDP).
func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.done = make(chan struct{})
	b.open = true
	done := b.done
	b.startReader()

	fn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case p, ok := <-b.recv:
			if !ok {
				return 0, net.ErrClosed
			}
			sizes[0] = copy(packets[0], p)
			eps[0] = peerEndpoint{}
			return 1, nil
		case <-done:
			return 0, net.ErrClosed
		}
	}
	return []conn.ReceiveFunc{fn}, 0, nil
}

// startReader launches (once) the goroutine that turns the blocking
// transport.ReadPacket into a channel. It exits when the transport errors (the
// Engine closed it) or stopReader releases it.
func (b *Bind) startReader() {
	b.readerOn.Do(func() {
		go func() {
			for {
				p, err := b.pt.ReadPacket()
				if err != nil {
					close(b.recv)
					return
				}
				select {
				case b.recv <- p:
				case <-b.dead:
					return
				}
			}
		}()
	})
}

// Close ends the current receive generation. It does not touch the transport.
func (b *Bind) Close() error {
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

// stopReader releases a reader blocked on delivering to recv. The Engine calls
// it (then transport.Close) during shutdown.
func (b *Bind) stopReader() { b.deadOnce.Do(func() { close(b.dead) }) }

// Send writes each packet to the transport. wireguard reuses bufs after Send
// returns, so each packet is copied first. Writes are serialized.
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	open := b.open
	b.mu.Unlock()
	if !open {
		return net.ErrClosed
	}
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	for _, buf := range bufs {
		if len(buf) == 0 {
			continue
		}
		pkt := make([]byte, len(buf))
		copy(pkt, buf)
		if err := b.pt.WritePacket(pkt); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint returns the fixed peer endpoint regardless of s.
func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) { return peerEndpoint{}, nil }

// SetMark is a no-op: there is no OS socket to mark.
func (b *Bind) SetMark(mark uint32) error { return nil }

// BatchSize is 1: a framed stream delivers one packet per read.
func (b *Bind) BatchSize() int { return 1 }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./wgengine/ -run TestBind -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./wgengine/` — clean.

- [ ] **Step 6: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/go.mod core/go.sum core/wgengine/bind.go core/wgengine/bind_test.go
git commit -m "feat(wgengine): conn.Bind adapter over PacketTransport

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Curve25519 key helpers

**Files:** Create `core/wgengine/keys.go`, `core/wgengine/keys_test.go`.

- [ ] **Step 1: Write the failing test**

Create `core/wgengine/keys_test.go`:
```go
package wgengine

import "testing"

func TestKeyGenerateAndDerive(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	if priv == (Key{}) {
		t.Fatal("private key is all-zero")
	}
	pub := priv.PublicKey()
	if pub == (Key{}) {
		t.Fatal("public key is all-zero")
	}
	if pub == priv {
		t.Fatal("public key equals private key")
	}
	// Derivation is deterministic.
	if priv.PublicKey() != pub {
		t.Fatal("PublicKey is not deterministic")
	}
}

func TestKeyHex(t *testing.T) {
	priv, _ := GeneratePrivateKey()
	if len(priv.Hex()) != 64 {
		t.Fatalf("Hex len = %d, want 64", len(priv.Hex()))
	}
}

func TestDistinctKeys(t *testing.T) {
	a, _ := GeneratePrivateKey()
	b, _ := GeneratePrivateKey()
	if a == b {
		t.Fatal("two generated keys are identical")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./wgengine/ -run TestKey -v`
Expected: FAIL — `undefined: GeneratePrivateKey`.

- [ ] **Step 3: Write the implementation**

Create `core/wgengine/keys.go`:
```go
package wgengine

import (
	"crypto/rand"
	"encoding/hex"

	"golang.org/x/crypto/curve25519"
)

// Key is a 32-byte Curve25519 key (WireGuard private or public).
type Key [32]byte

// GeneratePrivateKey returns a new, clamped Curve25519 private key.
func GeneratePrivateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, err
	}
	// Curve25519 clamping.
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k, nil
}

// PublicKey derives the Curve25519 public key for this private key.
func (k Key) PublicKey() Key {
	pub, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		// X25519 only errors on low-order inputs; the basepoint is valid and a
		// clamped key is non-zero, so this is unreachable in practice.
		panic("wgengine: deriving public key: " + err.Error())
	}
	var out Key
	copy(out[:], pub)
	return out
}

// Hex returns the lowercase hex encoding used by the WireGuard UAPI.
func (k Key) Hex() string { return hex.EncodeToString(k[:]) }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./wgengine/ -run 'TestKey|TestDistinct' -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./wgengine/` — clean.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/go.mod core/go.sum core/wgengine/keys.go core/wgengine/keys_test.go
git commit -m "feat(wgengine): Curve25519 key helpers (generate/derive/hex)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Engine (device wiring + config)

**Files:** Create `core/wgengine/engine.go`, `core/wgengine/engine_test.go`.

The engine_test.go smoke test uses `tun/netstack` (test-only) to build a device, bring it up, and close it cleanly — without a peer (no handshake), proving the wiring and clean shutdown.

- [ ] **Step 1: Write the failing test**

Create `core/wgengine/engine_test.go`:
```go
package wgengine

import (
	"net/netip"
	"testing"

	"github.com/g00dvin/gvpn/core/transport"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestEngineUpAndClose(t *testing.T) {
	priv, _ := GeneratePrivateKey()
	peer, _ := GeneratePrivateKey()

	tunDev, _, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("192.168.4.1")}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}

	// A self-closing PacketTransport stand-in: never delivers, closes cleanly.
	pt := transport.NewStreamTransport(newClosablePipe())

	eng, err := New(tunDev, pt, Config{
		PrivateKey:    priv,
		PeerPublicKey: peer.PublicKey(),
		AllowedIPs:    []string{"192.168.4.2/32"},
	}, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// newClosablePipe returns one end of a net.Pipe whose peer end is retained so
// the StreamTransport has a live, blocking io.ReadWriteCloser to read from.
func newClosablePipe() *pipeEnd {
	c1, c2 := netPipe()
	return &pipeEnd{ReadWriteCloser: c1, peer: c2}
}
```

NOTE for the implementer: keep this smoke test simple. Use `net.Pipe()` for the transport's underlying conn so `New` has something to wrap; the device won't handshake (no reachable peer), which is fine — the test only asserts `New` then `Close` succeed without hanging. Define the small `pipeEnd`/`netPipe` helpers (or inline `net.Pipe()` directly) however is cleanest; the goal is: build engine over a netstack TUN, then Close cleanly. If the helper indirection is awkward, simplify to:
```go
c1, c2 := net.Pipe()
defer c2.Close()
pt := transport.NewStreamTransport(c1)
```
and drop the helper functions. (Implement whichever is clean and compiles.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./wgengine/ -run TestEngineUpAndClose -v`
Expected: FAIL — `undefined: New`, `undefined: Config`.

- [ ] **Step 3: Write the implementation**

Create `core/wgengine/engine.go`:
```go
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./wgengine/ -run TestEngineUpAndClose -v`
Expected: PASS (builds device, brings up, closes without hanging). Also `/home/goodvin/.local/go/bin/go vet ./wgengine/`.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/go.mod core/go.sum core/wgengine/engine.go core/wgengine/engine_test.go
git commit -m "feat(wgengine): Engine (device wiring, UAPI config, New/Close)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: End-to-end tunnel (two engines over a real transport pair)

**Files:** Create `core/wgengine/e2e_test.go`.

This is the proof the whole component works: two `Engine`s, each on a `netstack` TUN, connected by a pair of `StreamTransport`s over a TCP loopback connection, complete a WireGuard handshake and exchange HTTP over the tunnel. (Pattern validated by the spike.)

- [ ] **Step 1: Write the test**

Create `core/wgengine/e2e_test.go`:
```go
package wgengine

import (
	"context"
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

func TestEndToEndTunnelHTTP(t *testing.T) {
	serverPriv, _ := GeneratePrivateKey()
	clientPriv, _ := GeneratePrivateKey()
	serverIP := netip.MustParseAddr("192.168.4.1")
	clientIP := netip.MustParseAddr("192.168.4.2")

	// netstack TUNs for both ends.
	serverTun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1420)
	if err != nil {
		t.Fatalf("server CreateNetTUN: %v", err)
	}
	clientTun, clientNet, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1420)
	if err != nil {
		t.Fatalf("client CreateNetTUN: %v", err)
	}

	// Transport pair over a TCP loopback connection.
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
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	a := <-ac
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}
	serverPT := transport.NewStreamTransport(a.c)
	clientPT := transport.NewStreamTransport(clientConn)

	// Engines. Server waits; client initiates (Endpoint set) with keepalive.
	serverEng, err := New(serverTun, serverPT, Config{
		PrivateKey:    serverPriv,
		PeerPublicKey: clientPriv.PublicKey(),
		AllowedIPs:    []string{clientIP.String() + "/32"},
	}, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("server New: %v", err)
	}
	defer serverEng.Close()

	clientEng, err := New(clientTun, clientPT, Config{
		PrivateKey:    clientPriv,
		PeerPublicKey: serverPriv.PublicKey(),
		AllowedIPs:    []string{"0.0.0.0/0"},
		Endpoint:      "gvpn-peer:0", // placeholder; arms client handshake
		Keepalive:     5,
	}, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	defer clientEng.Close()

	// HTTP server on the server netstack.
	httpLn, err := serverNet.ListenTCP(&net.TCPAddr{IP: serverIP.AsSlice(), Port: 80})
	if err != nil {
		t.Fatalf("netstack ListenTCP: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from gvpn wireguard tunnel")
	})}
	go srv.Serve(httpLn)
	defer srv.Close()

	// HTTP client over the client netstack; retry while the handshake completes.
	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: clientNet.DialContext},
		Timeout:   2 * time.Second,
	}
	deadline := time.Now().Add(15 * time.Second)
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
	if string(body) != "hello from gvpn wireguard tunnel" {
		t.Fatalf("tunnel HTTP body = %q, want the greeting (handshake/data path failed)", body)
	}
}
```

- [ ] **Step 2: Run the test**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./wgengine/ -run TestEndToEndTunnelHTTP -v -timeout 60s`
Expected: PASS — the WireGuard handshake completes over the StreamTransport pair and the HTTP GET returns the greeting through the tunnel. If it fails, this is a real integration problem (report BLOCKED with logs; do not weaken the assertion). You may temporarily set `device.LogLevelVerbose` to debug, then return to Silent.

- [ ] **Step 3: Run the whole package under race a few times (stability)**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race -count=3 ./wgengine/`
Expected: PASS all three. Report if flaky.

- [ ] **Step 4: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/wgengine/e2e_test.go
git commit -m "test(wgengine): end-to-end WireGuard tunnel over StreamTransport

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Dependency hygiene + final review + PR

**Files:** `core/go.mod`, `core/go.sum` (tidy only).

- [ ] **Step 1: Tidy modules and verify the whole repo**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go mod tidy
/home/goodvin/.local/go/bin/go test -race ./wgengine/
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test -race ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go build ./...
```
Expected: all PASS / clean. Commit any go.mod/go.sum changes from tidy:
```bash
cd /home/goodvin/git/gvpn
git add core/go.mod core/go.sum
git commit -m "chore(wgengine): go mod tidy for wireguard-go deps

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>" || echo "nothing to tidy"
```

- [ ] **Step 2: Confirm netstack stays test-only** (gomobile safety)

Run: `cd /home/goodvin/git/gvpn/core && grep -rl "tun/netstack" wgengine/ | grep -v _test.go`
Expected: NO output (netstack appears only in `_test.go`). If a non-test file imports it, that is a defect — move it.

- [ ] **Step 3: Opus final code + security review** (controller dispatches a fresh Opus subagent)

Review focus: the Bind concurrency (no goroutine leak; Close→receive funcs return net.ErrClosed; reader exits on transport close AND on stopReader; Send copies buffers; serialized writes), Engine shutdown ordering (device.Close → stopReader → pt.Close), correct conn.Bind contract, key clamping/derivation, no secret logging (private keys never logged), and that netstack is test-only.

- [ ] **Step 4: Push and open PR** (trivial / `gh` — Haiku)

```bash
cd /home/goodvin/git/gvpn
git push -u origin feat/wireguard-engine
gh pr create --base main --head feat/wireguard-engine \
  --title "WireGuard engine: wireguard-go over PacketTransport" \
  --body "Embeds wireguard-go and drives its traffic over our connection-oriented transport.PacketTransport instead of UDP — real IP traffic now flows through the VPN data path.

- core/wgengine/bind.go: Bind implements wireguard-go conn.Bind over a PacketTransport (background reader -> receive funcs; Send copies buffers; BatchSize 1; fixed point-to-point endpoint).
- core/wgengine/keys.go: Curve25519 key helpers (generate/derive/hex).
- core/wgengine/engine.go: Config + Engine (device wiring, WireGuard UAPI, New/Close).
- End-to-end test: two engines over a StreamTransport pair + tun/netstack complete a handshake and exchange HTTP through the tunnel (-race).

Pinned golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446. tun/netstack (gVisor) is test-only, so the gomobile build stays lean. No cgo.

Out of scope (later plans): server assembly wiring gate -> session -> this engine with a real TUN; client TUN integration (VpnService / NEPacketTunnelProvider); MTU tuning; throughput validation (design §7).

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

---

## Self-Review

**Spec coverage:** WireGuard Engine talking to the world only through `PacketTransport` → Task 1 (Bind) + Task 3 (Engine). Standard wireguard-go, no crypto changes → use the library as-is. Real IP flow proven → Task 4 (handshake + HTTP over the tunnel). Keys for config/provisioning → Task 2. Out of scope (later): server assembly (gate→session→engine with a real TUN), platform TUN integration, throughput/MTU validation — stated in the PR.

**Placeholder scan:** none — full code for bind/keys/engine and the e2e test. (Task 3's smoke test offers a simplification note, not a placeholder; the implementer picks the clean form and it compiles.)

**Type consistency:** `Bind`/`NewBind(transport.PacketTransport)*Bind`, `peerEndpoint`, `conn.Bind` methods exactly per the pinned API; `Key [32]byte` + `GeneratePrivateKey()(Key,error)` + `(Key).PublicKey()Key` + `(Key).Hex()string`; `Config{PrivateKey,PeerPublicKey Key; AllowedIPs []string; Keepalive int; Endpoint string}` + `(Config).uapi()`; `New(tun.Device, transport.PacketTransport, Config, int)(*Engine,error)` + `(*Engine).Close()error` calling `bind.stopReader()` then `pt.Close()`. Consistent across tasks; transport + wireguard APIs match verified sources.

**Concurrency note for the security review:** the Bind has three goroutine interactions — the background reader, the receive funcs, and Send. Close releases receive funcs (per-Open `done`); stopReader + transport.Close release the reader; the reader never blocks permanently (select on `recv` send vs `dead`). Verify no leak and no send-on-closed-channel.
