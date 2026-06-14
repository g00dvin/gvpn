# Session Manager + SESSION_BIND (reconnect/resume) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. This package is **pure Go (no cgo)** — keep it that way.
>
> **Per-task model assignment (controller's standing rule):**
> - **Sonnet** subagent — implements each code task (Tasks 1–4).
> - **Opus** (controller) — manages tasks, reviews each task's diff; dispatches a fresh **Opus** subagent for the final code + security review (Task 5).
> - **Haiku** subagent — `gh` push + PR (Task 5).

**Goal:** A server-side session registry plus the SESSION_BIND wire exchange that lets a reconnecting client rebind to its existing server session (preserving VPN identity/resume state across TCP/IP changes) instead of starting over.

**Architecture:** A new pure-Go `core/session` package. After the Plan 4 auth gate verifies a connection's device, the SESSION_BIND exchange runs as the next frame: the client sends a `SESSION_BIND` frame — a zero `SessionID` requests a brand-new session; a non-zero one resumes. The server's `Manager` (a concurrent registry keyed by SessionID) either mints a new `Session` (random SessionID + ResumeToken) or resumes an existing one after verifying it belongs to the authenticated device and the resume token matches (constant-time). The server replies with a `SESSION_BIND` frame carrying the assigned/confirmed SessionID + ResumeToken, which the client stores for its next reconnect. The live connection is never stored in the `Session` (it is swapped on every reconnect); the session holds identity + resume state only (design §6).

**Tech Stack:** Go 1.24, stdlib only (`crypto/rand`, `crypto/subtle`, `net`, `sync`, `time`, `io`). Builds on `core/frame` (`frame.TypeSessionBind`, `frame.ReadFrame`, `frame.WriteFrame`). Toolchain `/home/goodvin/.local/go/bin/go` (system `go` is 1.19, too old). cgo **not** required.

**Design reference:** `docs/superpowers/specs/2026-06-13-gvpn-transport-design.md` §5 (reconnection re-sends AUTH then SESSION_BIND), §6 (Session model: SessionID, DeviceID, ResumeToken, LastSeen). **Deviations from the design's `Session` struct, made deliberately and noted:** (1) `SessionID`/`DeviceID` are `[16]byte` (UUIDv4-sized) rather than `string`, for a fixed, allocation-bounded wire format; (2) `WGPublicKey` is omitted — it is unused until the wireguard-go data path lands and will be added then (YAGNI). The resume token is kept stable across resumes for phase 1; one-time-token rotation is a noted future enhancement.

---

## Conventions

- Toolchain: `/home/goodvin/.local/go/bin/go`. Run tests with:
  `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./session/`
  (No cgo/engine needed for `./session/`.)
- Branch `feat/session-bind` off `main` (already created). Work from `/home/goodvin/git/gvpn`.
- Commits end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Module path `github.com/g00dvin/gvpn/core`; import the frame codec as `github.com/g00dvin/gvpn/core/frame`.
- **No custom crypto:** SessionID/ResumeToken are `crypto/rand` bytes; resume-token comparison uses `crypto/subtle.ConstantTimeCompare`. Never compare the token with `==`/`bytes.Equal`.

## Existing APIs this plan builds on

From `core/frame` (on `main`):
- `frame.TypeSessionBind` (== 3), `frame.TypeData`.
- `frame.ReadFrame(r io.Reader) (Type, []byte, error)` — reads header + exact payload, validates version.
- `frame.WriteFrame(w io.Writer, t Type, payload []byte) error` — single Write.

The Plan 4 auth gate (`core/authgate`) yields the authenticated `DeviceID [16]byte` and the `net.Conn` positioned after the AUTH frame; `Manager.Bind` consumes the next frame (SESSION_BIND) on that conn. Wiring gate→session→data-path is the later server-assembly plan; this plan delivers the session component and proves it over loopback.

## File structure

```
core/session/codec.go        SESSION_BIND payload marshal/parse (fixed 48 bytes) + zero-ID sentinel
core/session/codec_test.go
core/session/manager.go       Session struct + Manager registry (create/resume/expiry/Sweep/Count)
core/session/manager_test.go
core/session/bind.go          (*Manager).Bind: server-side SESSION_BIND exchange over a net.Conn
core/session/bind_test.go
core/session/client.go        ClientBind: client-side SESSION_BIND exchange
core/session/client_test.go   end-to-end over TCP loopback (new + resume + negative)
```

---

## Task 1: SESSION_BIND codec

**Files:**
- Create: `core/session/codec.go`, `core/session/codec_test.go`

- [ ] **Step 1: Write the failing test**

Create `core/session/codec_test.go`:
```go
package session

import "testing"

func TestBindRoundTrip(t *testing.T) {
	var sid [sessionIDSize]byte
	var tok [resumeTokenSize]byte
	for i := range sid {
		sid[i] = byte(i + 1)
	}
	for i := range tok {
		tok[i] = byte(0xA0 + i)
	}

	b := marshalBind(sid, tok)
	if len(b) != bindPayloadSize {
		t.Fatalf("marshalBind len = %d, want %d", len(b), bindPayloadSize)
	}
	gotSID, gotTok, err := parseBind(b)
	if err != nil {
		t.Fatalf("parseBind: %v", err)
	}
	if gotSID != sid {
		t.Fatalf("sid = %x, want %x", gotSID, sid)
	}
	if gotTok != tok {
		t.Fatalf("token = %x, want %x", gotTok, tok)
	}
}

func TestParseBindWrongSize(t *testing.T) {
	if _, _, err := parseBind(make([]byte, bindPayloadSize-1)); err == nil {
		t.Fatal("parseBind(short): want error, got nil")
	}
}

func TestZeroSessionIDSentinel(t *testing.T) {
	var z [sessionIDSize]byte
	if zeroSessionID != z {
		t.Fatal("zeroSessionID is not all-zero")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./session/ -run TestBind -v`
Expected: FAIL — `undefined: marshalBind`, `undefined: bindPayloadSize`, etc.

- [ ] **Step 3: Write the implementation**

Create `core/session/codec.go`:
```go
// Package session implements the gvpn server-side session registry and the
// SESSION_BIND reconnect/resume exchange. After the auth gate verifies a
// device, a client binds (new) or rebinds (resume) its server session so VPN
// state survives TCP/IP changes. Pure Go, no cgo.
package session

import "errors"

// SESSION_BIND payload layout: SessionID(16) || ResumeToken(32) = 48 bytes,
// fixed. A fixed size keeps parsing allocation-free and lets the reader bound
// the frame strictly.
const (
	sessionIDSize   = 16
	resumeTokenSize = 32
	bindPayloadSize = sessionIDSize + resumeTokenSize // 48
)

// ErrBindSize is returned when a SESSION_BIND payload is not exactly
// bindPayloadSize bytes.
var ErrBindSize = errors.New("session: wrong SESSION_BIND payload size")

// zeroSessionID is the sentinel a client sends to request a brand-new session.
// A randomly minted SessionID is never all-zero in practice.
var zeroSessionID [sessionIDSize]byte

// marshalBind serializes a SESSION_BIND payload.
func marshalBind(sid [sessionIDSize]byte, token [resumeTokenSize]byte) []byte {
	b := make([]byte, bindPayloadSize)
	copy(b[:sessionIDSize], sid[:])
	copy(b[sessionIDSize:], token[:])
	return b
}

// parseBind deserializes a SESSION_BIND payload.
func parseBind(b []byte) (sid [sessionIDSize]byte, token [resumeTokenSize]byte, err error) {
	if len(b) != bindPayloadSize {
		return sid, token, ErrBindSize
	}
	copy(sid[:], b[:sessionIDSize])
	copy(token[:], b[sessionIDSize:])
	return sid, token, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./session/ -run 'TestBind|TestParseBind|TestZero' -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./session/` — clean.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/session/codec.go core/session/codec_test.go
git commit -m "feat(session): SESSION_BIND payload codec + zero-ID sentinel

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Session + Manager registry

**Files:**
- Create: `core/session/manager.go`, `core/session/manager_test.go`

This is the pure registry logic (no network). `create` mints a session; `resume` rebinds after verifying device + token + freshness; `Sweep` evicts expired. The `now` and `rand` fields are injectable for deterministic tests.

- [ ] **Step 1: Write the failing test**

Create `core/session/manager_test.go`:
```go
package session

import (
	"testing"
	"time"
)

// seqReader is a deterministic io.Reader for tests: it fills bytes with an
// incrementing pattern, so minted SessionIDs/tokens are non-zero and distinct.
type seqReader struct{ b byte }

func (r *seqReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
		r.b++
	}
	return len(p), nil
}

func TestManagerCreateAndResume(t *testing.T) {
	m := NewManager(time.Minute)
	m.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	m.rand = &seqReader{}
	dev := [16]byte{0xAA}

	s, err := m.create(dev)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if s.SessionID == zeroSessionID {
		t.Fatal("minted SessionID is the zero sentinel")
	}
	if s.DeviceID != dev {
		t.Fatalf("DeviceID = %x, want %x", s.DeviceID, dev)
	}
	if m.Count() != 1 {
		t.Fatalf("Count = %d, want 1", m.Count())
	}

	got, err := m.resume(dev, s.SessionID, s.ResumeToken)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got != s {
		t.Fatal("resume returned a different *Session; want the same instance")
	}
}

func TestManagerResumeWrongToken(t *testing.T) {
	m := NewManager(time.Minute)
	m.rand = &seqReader{}
	dev := [16]byte{1}
	s, _ := m.create(dev)
	bad := s.ResumeToken
	bad[0] ^= 0xFF
	if _, err := m.resume(dev, s.SessionID, bad); err == nil {
		t.Fatal("resume with wrong token: want error")
	}
}

func TestManagerResumeWrongDevice(t *testing.T) {
	m := NewManager(time.Minute)
	m.rand = &seqReader{}
	s, _ := m.create([16]byte{1})
	if _, err := m.resume([16]byte{2}, s.SessionID, s.ResumeToken); err == nil {
		t.Fatal("resume with wrong device: want error")
	}
}

func TestManagerResumeUnknown(t *testing.T) {
	m := NewManager(time.Minute)
	if _, err := m.resume([16]byte{1}, [16]byte{9}, [32]byte{}); err == nil {
		t.Fatal("resume unknown session: want error")
	}
}

func TestManagerResumeExpired(t *testing.T) {
	m := NewManager(time.Minute)
	m.rand = &seqReader{}
	base := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return base }
	dev := [16]byte{1}
	s, _ := m.create(dev)
	m.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, err := m.resume(dev, s.SessionID, s.ResumeToken); err == nil {
		t.Fatal("resume expired session: want error")
	}
}

func TestManagerSweepEvictsExpired(t *testing.T) {
	m := NewManager(time.Minute)
	m.rand = &seqReader{}
	base := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return base }
	m.create([16]byte{1})
	m.create([16]byte{2})
	if m.Count() != 2 {
		t.Fatalf("Count = %d, want 2", m.Count())
	}
	m.now = func() time.Time { return base.Add(2 * time.Minute) }
	m.Sweep()
	if m.Count() != 0 {
		t.Fatalf("Count after sweep = %d, want 0", m.Count())
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./session/ -run TestManager -v`
Expected: FAIL — `undefined: NewManager`.

- [ ] **Step 3: Write the implementation**

Create `core/session/manager.go`:
```go
package session

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"sync"
	"time"
)

// Resume errors. All map to the same outcome on the wire (the server drops the
// connection); they are distinguished only for server-side logging/metrics.
var (
	ErrUnknownSession = errors.New("session: unknown or expired session")
	ErrWrongDevice    = errors.New("session: session belongs to a different device")
	ErrBadResumeToken = errors.New("session: resume token mismatch")
)

// Session is the server-side resume anchor for one client tunnel. The live
// connection is NOT stored here — it is swapped on every reconnect; the session
// holds identity + resume state only (design §6).
type Session struct {
	SessionID   [16]byte
	DeviceID    [16]byte
	ResumeToken [32]byte
	LastSeen    time.Time
}

// Manager is the server-side session registry. Safe for concurrent use.
type Manager struct {
	ttl  time.Duration
	now  func() time.Time
	rand io.Reader
	mu   sync.Mutex
	byID map[[16]byte]*Session
}

// NewManager returns a registry whose sessions expire ttl after their last use.
func NewManager(ttl time.Duration) *Manager {
	return &Manager{
		ttl:  ttl,
		now:  time.Now,
		rand: rand.Reader,
		byID: make(map[[16]byte]*Session),
	}
}

// create mints a brand-new session for deviceID with a random SessionID and
// ResumeToken, stamped now.
func (m *Manager) create(deviceID [16]byte) (*Session, error) {
	var sid [16]byte
	var token [32]byte
	if _, err := io.ReadFull(m.rand, sid[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(m.rand, token[:]); err != nil {
		return nil, err
	}
	s := &Session{SessionID: sid, DeviceID: deviceID, ResumeToken: token, LastSeen: m.now()}
	m.mu.Lock()
	m.byID[sid] = s
	m.mu.Unlock()
	return s, nil
}

// resume rebinds an existing session. It must exist, be unexpired, belong to
// deviceID, and present the matching resume token (constant-time compare). On
// success LastSeen is refreshed.
func (m *Manager) resume(deviceID [16]byte, sid [16]byte, token [32]byte) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[sid]
	if !ok || m.now().Sub(s.LastSeen) > m.ttl {
		if ok {
			delete(m.byID, sid) // opportunistically drop the expired entry
		}
		return nil, ErrUnknownSession
	}
	if s.DeviceID != deviceID {
		return nil, ErrWrongDevice
	}
	if subtle.ConstantTimeCompare(s.ResumeToken[:], token[:]) != 1 {
		return nil, ErrBadResumeToken
	}
	s.LastSeen = m.now()
	return s, nil
}

// Sweep removes expired sessions. A server calls it periodically.
func (m *Manager) Sweep() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for id, s := range m.byID {
		if now.Sub(s.LastSeen) > m.ttl {
			delete(m.byID, id)
		}
	}
}

// Count returns the number of live sessions (tests/metrics).
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byID)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./session/ -run TestManager -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./session/` — clean.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/session/manager.go core/session/manager_test.go
git commit -m "feat(session): Session + Manager registry (create/resume/expiry)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Server-side Bind over a connection

**Files:**
- Create: `core/session/bind.go`, `core/session/bind_test.go`

- [ ] **Step 1: Write the failing test**

Create `core/session/bind_test.go`:
```go
package session

import (
	"net"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/frame"
)

func TestBindCreatesNewSession(t *testing.T) {
	m := NewManager(time.Minute)
	m.rand = &seqReader{}
	dev := [16]byte{7}

	client, server := net.Pipe()
	defer client.Close()

	type res struct {
		sid [16]byte
		tok [32]byte
		err error
	}
	cdone := make(chan res, 1)
	go func() {
		// New-session request: zero SessionID.
		frame.WriteFrame(client, frame.TypeSessionBind, marshalBind(zeroSessionID, [32]byte{}))
		typ, payload, err := frame.ReadFrame(client)
		if err != nil || typ != frame.TypeSessionBind {
			cdone <- res{err: err}
			return
		}
		sid, tok, _ := parseBind(payload)
		cdone <- res{sid: sid, tok: tok}
	}()

	s, err := m.Bind(dev, server)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	c := <-cdone
	if c.err != nil {
		t.Fatalf("client: %v", c.err)
	}
	if s.DeviceID != dev {
		t.Fatalf("session DeviceID = %x, want %x", s.DeviceID, dev)
	}
	if c.sid != s.SessionID || c.tok != s.ResumeToken {
		t.Fatal("client-received SessionID/token != server session")
	}
	if m.Count() != 1 {
		t.Fatalf("Count = %d, want 1", m.Count())
	}
}

func TestBindResumesExistingSession(t *testing.T) {
	m := NewManager(time.Minute)
	m.rand = &seqReader{}
	dev := [16]byte{7}
	orig, _ := m.create(dev)

	client, server := net.Pipe()
	defer client.Close()
	go func() {
		frame.WriteFrame(client, frame.TypeSessionBind, marshalBind(orig.SessionID, orig.ResumeToken))
		frame.ReadFrame(client) // drain ack
	}()

	s, err := m.Bind(dev, server)
	if err != nil {
		t.Fatalf("Bind resume: %v", err)
	}
	if s.SessionID != orig.SessionID {
		t.Fatal("resume returned a different SessionID")
	}
	if m.Count() != 1 {
		t.Fatalf("Count = %d, want 1 (no new session on resume)", m.Count())
	}
}

func TestBindRejectsNonBindFrame(t *testing.T) {
	m := NewManager(time.Minute)
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		frame.WriteFrame(client, frame.TypeData, []byte("x"))
		client.Close()
	}()
	if _, err := m.Bind([16]byte{1}, server); err == nil {
		t.Fatal("Bind on a DATA frame: want error, got nil")
	}
}

func TestBindRejectsBadResume(t *testing.T) {
	m := NewManager(time.Minute)
	m.rand = &seqReader{}
	dev := [16]byte{7}
	orig, _ := m.create(dev)
	bad := orig.ResumeToken
	bad[0] ^= 0xFF

	client, server := net.Pipe()
	defer client.Close()
	go func() {
		frame.WriteFrame(client, frame.TypeSessionBind, marshalBind(orig.SessionID, bad))
		client.Close()
	}()
	if _, err := m.Bind(dev, server); err == nil {
		t.Fatal("Bind with bad resume token: want error, got nil")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./session/ -run TestBind -v`
Expected: FAIL — `m.Bind undefined (type *Manager has no field or method Bind)`.

- [ ] **Step 3: Write the implementation**

Create `core/session/bind.go`:
```go
package session

import (
	"fmt"
	"net"

	"github.com/g00dvin/gvpn/core/frame"
)

// Bind runs the server side of the SESSION_BIND exchange on an
// already-authenticated connection. deviceID is the device the auth gate
// verified. It reads the client's SESSION_BIND frame:
//   - zero SessionID -> mint a new session;
//   - non-zero       -> resume the existing session (must belong to deviceID and
//     present the matching resume token).
// It then writes back a SESSION_BIND frame with the assigned/confirmed
// SessionID and ResumeToken and returns the bound session. On any failure it
// returns an error and writes nothing (the caller drops the connection),
// keeping every failure indistinguishable to the peer.
func (m *Manager) Bind(deviceID [16]byte, conn net.Conn) (*Session, error) {
	typ, payload, err := frame.ReadFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("session: read SESSION_BIND: %w", err)
	}
	if typ != frame.TypeSessionBind {
		return nil, fmt.Errorf("session: first post-auth frame is type %d, want SESSION_BIND", typ)
	}
	sid, token, err := parseBind(payload)
	if err != nil {
		return nil, err
	}

	var s *Session
	if sid == zeroSessionID {
		s, err = m.create(deviceID)
	} else {
		s, err = m.resume(deviceID, sid, token)
	}
	if err != nil {
		return nil, err
	}

	if err := frame.WriteFrame(conn, frame.TypeSessionBind, marshalBind(s.SessionID, s.ResumeToken)); err != nil {
		return nil, fmt.Errorf("session: write SESSION_BIND ack: %w", err)
	}
	return s, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./session/ -run TestBind -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./session/` — clean.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/session/bind.go core/session/bind_test.go
git commit -m "feat(session): server-side SESSION_BIND exchange (Manager.Bind)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Client-side bind + end-to-end

**Files:**
- Create: `core/session/client.go`, `core/session/client_test.go`

- [ ] **Step 1: Write the failing test**

Create `core/session/client_test.go`:
```go
package session

import (
	"net"
	"testing"
	"time"
)

// serveBind accepts connections and runs Manager.Bind for deviceID on each,
// closing the connection afterward. Returns the listener (close it to stop).
func serveBind(t *testing.T, m *Manager, deviceID [16]byte) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				m.Bind(deviceID, c) // ack is written before we close
			}(c)
		}
	}()
	return ln
}

func TestClientBindNewThenResume(t *testing.T) {
	m := NewManager(time.Minute)
	dev := [16]byte{0x42}
	ln := serveBind(t, m, dev)
	defer ln.Close()

	// First connect: brand-new session (zero SessionID).
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	var zsid [16]byte
	var ztok [32]byte
	sid, tok, err := ClientBind(c1, zsid, ztok)
	c1.Close()
	if err != nil {
		t.Fatalf("ClientBind new: %v", err)
	}
	if sid == zsid {
		t.Fatal("assigned SessionID is the zero sentinel")
	}

	// Reconnect: resume with the stored SessionID + token.
	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	sid2, tok2, err := ClientBind(c2, sid, tok)
	c2.Close()
	if err != nil {
		t.Fatalf("ClientBind resume: %v", err)
	}
	if sid2 != sid || tok2 != tok {
		t.Fatal("resume returned a different SessionID/token")
	}
	if m.Count() != 1 {
		t.Fatalf("Count = %d, want 1 (resume must not mint a new session)", m.Count())
	}
}

func TestClientResumeWrongTokenFails(t *testing.T) {
	m := NewManager(time.Minute)
	m.rand = &seqReader{}
	dev := [16]byte{1}
	orig, _ := m.create(dev)
	ln := serveBind(t, m, dev)
	defer ln.Close()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	bad := orig.ResumeToken
	bad[0] ^= 0xFF
	// Server's Bind fails and closes without an ack, so the client's read errors.
	if _, _, err := ClientBind(c, orig.SessionID, bad); err == nil {
		t.Fatal("ClientBind with wrong token: want error, got nil")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./session/ -run TestClient -v`
Expected: FAIL — `undefined: ClientBind`.

- [ ] **Step 3: Write the implementation**

Create `core/session/client.go`:
```go
package session

import (
	"fmt"
	"net"

	"github.com/g00dvin/gvpn/core/frame"
)

// ClientBind runs the client side of the SESSION_BIND exchange, sent as the
// frame right after AUTH. For a brand-new session pass the zero SessionID (the
// token is then ignored); to resume, pass the SessionID and ResumeToken stored
// from a previous bind. It returns the SessionID and ResumeToken the server
// assigned/confirmed, which the client persists for its next reconnect.
func ClientBind(conn net.Conn, sid [16]byte, token [32]byte) (newSID [16]byte, newToken [32]byte, err error) {
	if err = frame.WriteFrame(conn, frame.TypeSessionBind, marshalBind(sid, token)); err != nil {
		return newSID, newToken, fmt.Errorf("session: write SESSION_BIND: %w", err)
	}
	typ, payload, err := frame.ReadFrame(conn)
	if err != nil {
		return newSID, newToken, fmt.Errorf("session: read SESSION_BIND ack: %w", err)
	}
	if typ != frame.TypeSessionBind {
		return newSID, newToken, fmt.Errorf("session: ack frame is type %d, want SESSION_BIND", typ)
	}
	return parseBind(payload)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./session/ -v`
Expected: PASS (whole `session` package). Also `/home/goodvin/.local/go/bin/go vet ./session/` — clean.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/session/client.go core/session/client_test.go
git commit -m "feat(session): client SESSION_BIND + end-to-end resume tests

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Final review + security review + PR

**Files:** none (verification + PR only).

- [ ] **Step 1: Full package suite under race + vet**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test -race ./session/
/home/goodvin/.local/go/bin/go vet ./session/
```
Expected: PASS, vet clean.

- [ ] **Step 2: Whole-repo build sanity (cgo on, includes gosttls)**

Run:
```bash
cd /home/goodvin/git/gvpn/core
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go build ./...
```
Expected: builds. (If the gost engine is unavailable in the execution environment, gosttls may fail to link — acceptable here as long as `./session/` is green; note it. CI provisions the engine.)

- [ ] **Step 3: Opus final code + security review** (controller dispatches a fresh Opus subagent)

Security checklist to confirm (file:line evidence): (1) resume token compared with `subtle.ConstantTimeCompare`, never `==`/`bytes.Equal`; (2) SessionID and ResumeToken come from `crypto/rand` (full 16/32 bytes); (3) a session can only be resumed by the SAME authenticated DeviceID that owns it; (4) expired sessions are rejected on resume and evicted by Sweep; (5) all resume failures (unknown/expired/wrong-device/bad-token/non-BIND-frame) produce no ack and an indistinguishable outcome to the peer; (6) the bind read is bounded (frame codec caps payload; parseBind requires exactly 48 bytes); (7) no SessionID/ResumeToken logged.

- [ ] **Step 4: Push and open PR** (trivial / `gh` — Haiku)

```bash
cd /home/goodvin/git/gvpn
git push -u origin feat/session-bind
gh pr create --base main --head feat/session-bind \
  --title "Session manager + SESSION_BIND (reconnect/resume)" \
  --body "Implements design §5/§6: a server-side session registry and the SESSION_BIND exchange so a reconnecting client rebinds its existing session (identity/resume state preserved across TCP/IP changes) instead of starting over.

- core/session/codec.go: fixed 48-byte SESSION_BIND payload (SessionID||ResumeToken); zero SessionID = new-session request.
- core/session/manager.go: Session + concurrent Manager (create/resume/expiry/Sweep). Resume verifies device ownership + constant-time token + freshness.
- core/session/bind.go: server Manager.Bind over a net.Conn (new vs resume, writes ack).
- core/session/client.go: ClientBind (sent right after AUTH).

Pure Go, tested with -race: codec, registry logic, server bind, and end-to-end new+resume over TCP loopback, plus negative cases (wrong token/device, expired, non-BIND frame).

Deviations (noted in plan): SessionID/DeviceID are [16]byte (not string) for a fixed wire format; WGPublicKey omitted until the data path needs it; resume token stable across resumes (rotation is a future enhancement).

Out of scope (later plans): wiring gate -> session -> wireguard-go data path in the server; sending AUTH+SESSION_BIND on each reconnect through the transport adapter.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

---

## Self-Review

**Spec coverage (design §5/§6):** Session struct (identity + resume state, no live conn) → Task 2. SESSION_BIND rebind of an existing server session on reconnect → Tasks 3 (server) + 4 (client). New-session issuance → Task 2/3 (zero-ID sentinel). Resume bound to the session + device → Task 2 (`resume` checks DeviceID + constant-time token). Expiry/`LastSeen` → Task 2 (ttl, Sweep). The reconnect sequence "re-send AUTH then SESSION_BIND" composes: the auth gate (Plan 4) yields DeviceID + conn, then `Manager.Bind(deviceID, conn)` runs — server-assembly wiring is a later plan (noted).

**Placeholder scan:** none — every code step has complete, compilable code.

**Type consistency:** `sessionIDSize=16`, `resumeTokenSize=32`, `bindPayloadSize=48`, `zeroSessionID [16]byte`, `marshalBind([16]byte,[32]byte)[]byte`, `parseBind([]byte)([16]byte,[32]byte,error)` (Task 1, used by Tasks 3/4). `Session{SessionID[16],DeviceID[16],ResumeToken[32],LastSeen}`, `NewManager(ttl)*Manager` + injectable `now`/`rand`, `create([16]byte)(*Session,error)`, `resume([16]byte,[16]byte,[32]byte)(*Session,error)`, `Sweep()`, `Count()int` (Task 2). `(*Manager).Bind([16]byte,net.Conn)(*Session,error)` (Task 3). `ClientBind(net.Conn,[16]byte,[32]byte)([16]byte,[32]byte,error)` (Task 4). All consistent; frame APIs match `core/frame`.
