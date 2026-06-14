# Reconnecting Transport Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** A `PacketTransport` that hides connection loss — transparently re-dialing (with backoff + a fresh `SESSION_BIND` frame) and retrying reads/writes, returning an error only after `Close`.

**Architecture:** Builds on the `core/frame` codec and the `PacketTransport` interface from Plan 1. A `Dialer` func abstracts connection establishment (a real `DialTCP`, plus injectable fakes for tests). `ReconnectingTransport` owns the current framed connection behind a generation counter: read/write paths snapshot the current connection, and on failure force a single serialized reconnect keyed on that generation, so concurrent readers and writers never dial twice. No TLS yet (Plan 3 wraps the dialer); fully testable in-memory via `net.Pipe`. Resolves spec-review finding M3 and design §5.

**Tech Stack:** Go 1.24 (toolchain at `/home/goodvin/.local/go/bin/go` — the system `go` is 1.19 and will NOT build this), stdlib only (`context`, `net`, `sync`, `time`, `io`, `errors`).

**Design reference:** `docs/superpowers/specs/2026-06-13-gvpn-transport-design.md` §5.

---

## Conventions for every task

- **Go toolchain:** use `/home/goodvin/.local/go/bin/go` for ALL go commands. Example: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./transport/ -v`.
- Branch is already created: `feat/reconnecting-transport`. Work from `/home/goodvin/git/gvpn`.
- Commit messages end with: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- All concurrency tests MUST pass under `-race`.

## File structure

```
core/transport/dialer.go               Dialer type + DialTCP
core/transport/dialer_test.go          DialTCP integration test
core/transport/reconnecting.go         ReconnectingTransport + ErrClosed
core/transport/reconnecting_test.go    pipeDialer harness + happy-path/reconnect/close tests
```
(`core/transport/transport.go` from Plan 1 is unchanged.)

---

## Task 1: Dialer type + DialTCP

**Files:**
- Create: `core/transport/dialer.go`
- Test: `core/transport/dialer_test.go`

- [ ] **Step 1: Write the failing test**

Create `core/transport/dialer_test.go`:
```go
package transport

import (
	"context"
	"io"
	"net"
	"testing"
)

func TestDialTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Write([]byte("ok"))
		c.Close()
	}()

	conn, err := DialTCP(ln.Addr().String())(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("got %q, want %q", buf, "ok")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./transport/ -run TestDialTCP -v`
Expected: FAIL — `undefined: DialTCP`.

- [ ] **Step 3: Write the implementation**

Create `core/transport/dialer.go`:
```go
package transport

import (
	"context"
	"io"
	"net"
)

// Dialer establishes a fresh framed connection. The context bounds the dial.
// A later plan wraps the TCP dialer with GOST TLS; the rest of the transport is
// agnostic to what the Dialer returns.
type Dialer func(ctx context.Context) (io.ReadWriteCloser, error)

// DialTCP returns a Dialer that opens plain TCP connections to address
// ("host:port").
func DialTCP(address string) Dialer {
	return func(ctx context.Context) (io.ReadWriteCloser, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", address)
	}
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./transport/ -run TestDialTCP -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./transport/` — clean.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/transport/dialer.go core/transport/dialer_test.go
git commit -m "feat(transport): Dialer type + DialTCP

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: ReconnectingTransport (implementation + happy-path test)

**Files:**
- Create: `core/transport/reconnecting.go`
- Test: `core/transport/reconnecting_test.go`

This task writes the full `ReconnectingTransport` and a happy-path (single connection) test. Reconnect/close behavior is exercised in Task 3.

- [ ] **Step 1: Write the failing test (harness + happy path)**

Create `core/transport/reconnecting_test.go`:
```go
package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/frame"
)

// pipeDialer hands out net.Pipe connections and exposes the server ends on
// serverC. It can be told to fail the first failN dials.
type pipeDialer struct {
	serverC chan net.Conn
	mu      sync.Mutex
	dials   int
	failN   int
}

func newPipeDialer(failN int) *pipeDialer {
	return &pipeDialer{serverC: make(chan net.Conn), failN: failN}
}

func (d *pipeDialer) dial(ctx context.Context) (io.ReadWriteCloser, error) {
	d.mu.Lock()
	d.dials++
	fail := d.failN > 0
	if fail {
		d.failN--
	}
	d.mu.Unlock()
	if fail {
		return nil, errors.New("pipeDialer: simulated dial failure")
	}
	cli, srv := net.Pipe()
	d.serverC <- srv
	return cli, nil
}

func (d *pipeDialer) dialCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

func mustReadFrame(t *testing.T, r io.Reader, wantType frame.Type, wantPayload string) {
	t.Helper()
	typ, p, err := frame.ReadFrame(r)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if typ != wantType || string(p) != wantPayload {
		t.Fatalf("frame = (%d,%q), want (%d,%q)", typ, p, wantType, wantPayload)
	}
}

func TestReconnectingHappyPath(t *testing.T) {
	d := newPipeDialer(0)
	tr := NewReconnectingTransport(ReconnectingConfig{
		Dialer:       d.dial,
		SessionToken: []byte("sess-1"),
		MinBackoff:   time.Millisecond,
		MaxBackoff:   5 * time.Millisecond,
	})
	defer tr.Close()

	// First WritePacket triggers the lazy dial; run it in a goroutine because
	// net.Pipe is synchronous.
	writeErr := make(chan error, 1)
	go func() { writeErr <- tr.WritePacket([]byte("hello")) }()

	srv := <-d.serverC
	mustReadFrame(t, srv, frame.TypeSessionBind, "sess-1")
	mustReadFrame(t, srv, frame.TypeData, "hello")
	if err := <-writeErr; err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	// Server -> client DATA frame, read via ReadPacket.
	if err := frame.WriteFrame(srv, frame.TypeData, []byte("world")); err != nil {
		t.Fatal(err)
	}
	got, err := tr.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if string(got) != "world" {
		t.Fatalf("packet = %q, want %q", got, "world")
	}

	if d.dialCount() != 1 {
		t.Fatalf("dials = %d, want 1", d.dialCount())
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./transport/ -run TestReconnectingHappyPath -v`
Expected: FAIL — `undefined: NewReconnectingTransport`, `undefined: ReconnectingConfig`.

- [ ] **Step 3: Write the implementation**

Create `core/transport/reconnecting.go`:
```go
package transport

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/g00dvin/gvpn/core/frame"
)

// ErrClosed is returned by a ReconnectingTransport after Close.
var ErrClosed = errors.New("transport: closed")

const (
	defaultMinBackoff  = 100 * time.Millisecond
	defaultMaxBackoff  = 30 * time.Second
	defaultDialTimeout = 10 * time.Second
)

// ReconnectingConfig configures a ReconnectingTransport.
type ReconnectingConfig struct {
	// Dialer establishes a new connection. Required.
	Dialer Dialer
	// SessionToken, if non-empty, is sent in a SESSION_BIND frame immediately
	// after every (re)connect so the server can rebind an existing session.
	SessionToken []byte
	// MinBackoff/MaxBackoff bound the exponential reconnect backoff.
	MinBackoff time.Duration
	MaxBackoff time.Duration
	// DialTimeout bounds each dial attempt.
	DialTimeout time.Duration
}

// ReconnectingTransport is a PacketTransport that hides connection loss. When
// the underlying connection fails, ReadPacket and WritePacket transparently
// re-dial (with exponential backoff and a fresh SESSION_BIND) and retry; they
// return ErrClosed only after Close. This is the contract WireGuard relies on:
// it observes a stall across a network change, never an EOF.
type ReconnectingTransport struct {
	dial         Dialer
	sessionToken []byte
	minBackoff   time.Duration
	maxBackoff   time.Duration
	dialTimeout  time.Duration

	connMu  sync.Mutex // guards conn, gen, closed
	conn    io.ReadWriteCloser
	gen     uint64
	closed  bool
	closeCh chan struct{}

	dialMu  sync.Mutex // serializes (re)dial attempts
	writeMu sync.Mutex // serializes writes to the current conn
}

// NewReconnectingTransport creates a transport from cfg. It dials lazily: the
// first ReadPacket or WritePacket establishes the connection.
func NewReconnectingTransport(cfg ReconnectingConfig) *ReconnectingTransport {
	t := &ReconnectingTransport{
		dial:         cfg.Dialer,
		sessionToken: cfg.SessionToken,
		minBackoff:   cfg.MinBackoff,
		maxBackoff:   cfg.MaxBackoff,
		dialTimeout:  cfg.DialTimeout,
		closeCh:      make(chan struct{}),
	}
	if t.minBackoff <= 0 {
		t.minBackoff = defaultMinBackoff
	}
	if t.maxBackoff <= 0 {
		t.maxBackoff = defaultMaxBackoff
	}
	if t.dialTimeout <= 0 {
		t.dialTimeout = defaultDialTimeout
	}
	return t
}

func (t *ReconnectingTransport) isClosed() bool {
	t.connMu.Lock()
	defer t.connMu.Unlock()
	return t.closed
}

// ensure returns a usable connection and its generation. If hasBad is true and
// the current generation equals badGen, the current connection is treated as
// dead and a reconnect is forced. ensure blocks (with backoff) until a
// connection is established or the transport is closed.
func (t *ReconnectingTransport) ensure(badGen uint64, hasBad bool) (io.ReadWriteCloser, uint64, error) {
	// Fast path: a good connection already exists.
	t.connMu.Lock()
	if t.closed {
		t.connMu.Unlock()
		return nil, 0, ErrClosed
	}
	if t.conn != nil && !(hasBad && t.gen == badGen) {
		c, g := t.conn, t.gen
		t.connMu.Unlock()
		return c, g, nil
	}
	t.connMu.Unlock()

	// Slow path: serialize dialing so only one goroutine reconnects at a time.
	t.dialMu.Lock()
	defer t.dialMu.Unlock()

	// Re-check: another goroutine may have reconnected while we waited.
	t.connMu.Lock()
	if t.closed {
		t.connMu.Unlock()
		return nil, 0, ErrClosed
	}
	if t.conn != nil && !(hasBad && t.gen == badGen) {
		c, g := t.conn, t.gen
		t.connMu.Unlock()
		return c, g, nil
	}
	old := t.conn
	t.conn = nil
	t.connMu.Unlock()
	if old != nil {
		_ = old.Close()
	}

	backoff := t.minBackoff
	for {
		if t.isClosed() {
			return nil, 0, ErrClosed
		}
		conn, err := t.dialOnce()
		if err == nil {
			t.connMu.Lock()
			if t.closed {
				t.connMu.Unlock()
				_ = conn.Close()
				return nil, 0, ErrClosed
			}
			t.conn = conn
			t.gen++
			g := t.gen
			t.connMu.Unlock()
			return conn, g, nil
		}
		select {
		case <-t.closeCh:
			return nil, 0, ErrClosed
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > t.maxBackoff {
			backoff = t.maxBackoff
		}
	}
}

// dialOnce performs a single dial and sends the SESSION_BIND frame (if any).
func (t *ReconnectingTransport) dialOnce() (io.ReadWriteCloser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), t.dialTimeout)
	defer cancel()
	conn, err := t.dial(ctx)
	if err != nil {
		return nil, err
	}
	if len(t.sessionToken) > 0 {
		if err := frame.WriteFrame(conn, frame.TypeSessionBind, t.sessionToken); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// ReadPacket returns the next DATA-frame payload, transparently reconnecting on
// failure. It returns ErrClosed only after Close.
func (t *ReconnectingTransport) ReadPacket() ([]byte, error) {
	var badGen uint64
	var hasBad bool
	for {
		conn, gen, err := t.ensure(badGen, hasBad)
		if err != nil {
			return nil, err
		}
		typ, payload, rerr := frame.ReadFrame(conn)
		if rerr != nil {
			if t.isClosed() {
				return nil, ErrClosed
			}
			badGen, hasBad = gen, true
			continue
		}
		if typ == frame.TypeData {
			return payload, nil
		}
		// Non-DATA frames (heartbeat, control) are skipped at this layer.
	}
}

// WritePacket sends p as a DATA frame, transparently reconnecting on failure.
func (t *ReconnectingTransport) WritePacket(p []byte) error {
	var badGen uint64
	var hasBad bool
	for {
		conn, gen, err := t.ensure(badGen, hasBad)
		if err != nil {
			return err
		}
		t.writeMu.Lock()
		werr := frame.WriteFrame(conn, frame.TypeData, p)
		t.writeMu.Unlock()
		if werr != nil {
			if t.isClosed() {
				return ErrClosed
			}
			badGen, hasBad = gen, true
			continue
		}
		return nil
	}
}

// Close releases the transport. In-flight and subsequent Read/Write calls
// return ErrClosed.
func (t *ReconnectingTransport) Close() error {
	t.connMu.Lock()
	if t.closed {
		t.connMu.Unlock()
		return nil
	}
	t.closed = true
	close(t.closeCh)
	c := t.conn
	t.conn = nil
	t.connMu.Unlock()
	if c != nil {
		return c.Close()
	}
	return nil
}

var _ PacketTransport = (*ReconnectingTransport)(nil)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./transport/ -run TestReconnectingHappyPath -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./transport/` — clean.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/transport/reconnecting.go core/transport/reconnecting_test.go
git commit -m "feat(transport): ReconnectingTransport (happy path)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Reconnect + close behavior tests

**Files:**
- Test: `core/transport/reconnecting_test.go` (append)

These tests exercise the reconnect and Close paths already implemented in Task 2. If a test fails, the bug is in `reconnecting.go` — fix it there; do not weaken the test.

- [ ] **Step 1: Append the tests**

Append to `core/transport/reconnecting_test.go`:
```go
func TestReconnectingReconnectsAfterDrop(t *testing.T) {
	d := newPipeDialer(0)
	tr := NewReconnectingTransport(ReconnectingConfig{
		Dialer:       d.dial,
		SessionToken: []byte("sess"),
		MinBackoff:   time.Millisecond,
		MaxBackoff:   5 * time.Millisecond,
	})
	defer tr.Close()

	// First connection.
	go func() { tr.WritePacket([]byte("p1")) }()
	srv1 := <-d.serverC
	mustReadFrame(t, srv1, frame.TypeSessionBind, "sess")
	mustReadFrame(t, srv1, frame.TypeData, "p1")

	// Drop the connection from the server side.
	srv1.Close()

	// The next write must transparently reconnect (second dial) and resend bind.
	writeErr := make(chan error, 1)
	go func() { writeErr <- tr.WritePacket([]byte("p2")) }()
	srv2 := <-d.serverC
	mustReadFrame(t, srv2, frame.TypeSessionBind, "sess")
	mustReadFrame(t, srv2, frame.TypeData, "p2")
	if err := <-writeErr; err != nil {
		t.Fatalf("WritePacket after drop: %v", err)
	}
	if got := d.dialCount(); got != 2 {
		t.Fatalf("dials = %d, want 2", got)
	}
}

func TestReconnectingCloseUnblocksBlockedRead(t *testing.T) {
	d := newPipeDialer(0)
	tr := NewReconnectingTransport(ReconnectingConfig{
		Dialer:     d.dial,
		MinBackoff: time.Millisecond,
		MaxBackoff: 5 * time.Millisecond,
	})

	errc := make(chan error, 1)
	go func() {
		_, err := tr.ReadPacket()
		errc <- err
	}()

	// No SessionToken => no bind frame; the client just blocks reading.
	<-d.serverC
	time.Sleep(10 * time.Millisecond) // ensure ReadPacket is parked in ReadFrame

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errc:
		if err != ErrClosed {
			t.Fatalf("err = %v, want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadPacket did not return after Close")
	}
}

func TestReconnectingCloseUnblocksBackoff(t *testing.T) {
	d := newPipeDialer(1 << 30) // every dial fails => stuck in backoff
	tr := NewReconnectingTransport(ReconnectingConfig{
		Dialer:     d.dial,
		MinBackoff: 5 * time.Millisecond,
		MaxBackoff: 10 * time.Millisecond,
	})

	errc := make(chan error, 1)
	go func() {
		_, err := tr.ReadPacket()
		errc <- err
	}()
	time.Sleep(20 * time.Millisecond) // let it enter the backoff loop

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errc:
		if err != ErrClosed {
			t.Fatalf("err = %v, want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadPacket did not return after Close during backoff")
	}
}
```

- [ ] **Step 2: Run the tests (expect PASS — logic already implemented)**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./transport/ -run TestReconnecting -v`
Expected: PASS for all four `TestReconnecting*` tests under `-race`. If any fails, fix `reconnecting.go` (not the test) and re-run.

- [ ] **Step 3: Full suite + vet**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./... && /home/goodvin/.local/go/bin/go vet ./...`
Expected: all packages PASS, vet clean.

- [ ] **Step 4: Commit, push, open PR**

```bash
cd /home/goodvin/git/gvpn
git add core/transport/reconnecting_test.go
git commit -m "test(transport): reconnect + close behavior under -race

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push -u origin feat/reconnecting-transport
gh pr create --title "Reconnecting transport adapter" \
  --body "Implements Plan 2: ReconnectingTransport hides connection loss (transparent re-dial + SESSION_BIND, blocks across reconnects, errors only on Close). Resolves spec-review M3 / design §5. Still no TLS (Plan 3). Pure Go, -race clean.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```
Expected: branch pushed, PR created. Report the PR URL.

---

## Self-Review

**Spec coverage (Plan 2 scope):**
- Reconnection hidden behind PacketTransport (design §5 / M3) → Task 2 (`ensure`/`ReadPacket`/`WritePacket` block + retry; `Close` → ErrClosed) and Task 3 (drop + close tests). ✓
- SESSION_BIND on every (re)connect (design §4 frame type, §5) → `dialOnce` + tested in Tasks 2/3. ✓
- Real transport entry point → `DialTCP` (Task 1); GOST TLS wraps this dialer in Plan 3 (out of scope here). ✓
- OS network-change triggers (L3) and heartbeat (§13) are deferred to a later plan (the client wiring/keepalive plan) — not in Plan 2 scope.

**Placeholder scan:** No TBD/TODO. Every step has complete code or an exact command. ✓

**Type consistency:** `Dialer = func(context.Context) (io.ReadWriteCloser, error)`; `ReconnectingConfig{Dialer, SessionToken, MinBackoff, MaxBackoff, DialTimeout}`; `NewReconnectingTransport(ReconnectingConfig) *ReconnectingTransport`; methods `ReadPacket()/WritePacket([]byte)/Close()` (satisfies `PacketTransport`); `ErrClosed`; `frame.TypeSessionBind`/`frame.TypeData`/`frame.WriteFrame`/`frame.ReadFrame` from Plan 1. Test harness `pipeDialer.dial` matches the `Dialer` signature. Consistent across tasks. ✓
