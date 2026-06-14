# In-Tunnel AUTH Gate + Decoy Fallback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This package is **pure Go (no cgo)** — keep it that way (the one cgo dependency, `gosttls`, must not be imported by non-test code here).
>
> **Per-task model assignment (controller's rule for this plan):**
> - **Sonnet** subagent — writes/tests/executes each implementation task (Tasks 1–6).
> - **Haiku** subagent — trivial steps and `gh` usage (Task 7 PR creation).
> - **Opus** (controller) — manages tasks, reviews each task's diff, runs the security review.

**Goal:** A server-side in-tunnel authentication gate that inspects a connection's first frame after GOST TLS: a valid AUTH token switches the connection to the VPN data path; anything else (bad token, HTTP, garbage, replay) is transparently reverse-proxied to a decoy origin — plus the client-side AUTH-frame emitter.

**Architecture:** A new pure-Go `core/authgate` package. The AUTH token is `HMAC-SHA256(PSK, version||deviceID||nonce||timestamp)` — high-entropy, replay-bounded, unlinkable (design §3). The `Gate` reads the first frame off a (already TLS-terminated) `net.Conn`: it validates the frame header strictly, parses + verifies the token against a per-device PSK from a `DeviceStore`, and checks a `ReplayCache`. Success returns the conn positioned right after the AUTH frame for the data path; failure hands the conn (with the bytes already read replayed as a prefix) to a `Decoy` that reverse-proxies to a configured plain-TCP origin. The client calls `WriteAuth` as its first frame after each (re)connect.

**Tech Stack:** Go 1.24, stdlib only (`crypto/hmac`, `crypto/sha256`, `crypto/rand`, `net`, `io`, `sync`, `time`). Builds on `core/frame` (typed frame codec). Toolchain `/home/goodvin/.local/go/bin/go` (system `go` is 1.19, too old). cgo **not** required for this package.

**Design reference:** `docs/superpowers/specs/2026-06-13-gvpn-transport-design.md` §3 (crypto/camouflage, decoy), §4 (frame types: `AUTH`), §5 (reconnect re-sends AUTH).

---

## Conventions

- Toolchain: `/home/goodvin/.local/go/bin/go`. Run package tests with:
  `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./authgate/`
  (No cgo/engine needed for `./authgate/`. The repo-wide `go test ./...` also builds `gosttls`, which needs `CGO_ENABLED=1` + the gost engine — out of scope for these per-package runs.)
- Branch `feat/auth-gate` off `main`. Work from `/home/goodvin/git/gvpn`.
- Commits end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Module path is `github.com/g00dvin/gvpn/core`; import the frame codec as `github.com/g00dvin/gvpn/core/frame`.
- **No custom crypto:** HMAC-SHA256 via Go stdlib is the token MAC (standard primitive, not the transport crypto — GOST TLS already handles that). Use `hmac.Equal` for constant-time comparison. Never weaken this.

## Existing APIs this plan builds on (do not re-implement)

From `core/frame` (already on `main`):
- `frame.HeaderSize = 4`, `frame.Version1 uint8 = 1`, `frame.MaxPayloadSize = 65535`.
- `frame.Type` constants: `frame.TypeData=0`, `frame.TypeAuth=1`, `frame.TypeHeartbeat=2`, `frame.TypeSessionBind=3`, `frame.TypeControl=4`.
- `frame.Header{Version uint8; Type Type; Length uint16}` and `frame.ParseHeader(b []byte) (Header, error)`.
- `frame.ReadFrame(r io.Reader) (Type, []byte, error)` — reads header + exact payload via `io.ReadFull`, validates version.
- `frame.WriteFrame(w io.Writer, t Type, payload []byte) error` — single `Write`.

## File structure

```
core/authgate/token.go         AUTH token: Token, MakeToken, Marshal/ParseToken, Verify, computeMAC
core/authgate/token_test.go
core/authgate/replay.go        ReplayCache (nonce anti-replay, TTL eviction, concurrent-safe)
core/authgate/replay_test.go
core/authgate/registry.go      DeviceStore interface + MapStore (DeviceID -> PSK)
core/authgate/registry_test.go
core/authgate/decoy.go         Decoy interface + TCPDecoy (reverse-proxy to origin)
core/authgate/decoy_test.go
core/authgate/gate.go          Gate, Result, Handle, recordingReader
core/authgate/gate_test.go
core/authgate/client.go        WriteAuth (client first-frame emitter)
core/authgate/client_test.go   end-to-end over TCP loopback (authenticated + decoy)
```

---

## Task 1: AUTH token (construct / parse / verify)

**Files:**
- Create: `core/authgate/token.go`, `core/authgate/token_test.go`

- [ ] **Step 1: Write the failing test**

Create `core/authgate/token_test.go`:
```go
package authgate

import (
	"testing"
	"time"
)

func TestTokenRoundTripAndVerify(t *testing.T) {
	psk := []byte("super-secret-psk")
	dev := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	now := time.Unix(1_700_000_000, 0)

	raw, err := MakeToken(psk, dev, now)
	if err != nil {
		t.Fatalf("MakeToken: %v", err)
	}
	if len(raw) != TokenSize {
		t.Fatalf("token size = %d, want %d", len(raw), TokenSize)
	}
	tok, err := ParseToken(raw)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if tok.DeviceID != dev {
		t.Fatalf("DeviceID = %x, want %x", tok.DeviceID, dev)
	}
	if err := tok.Verify(psk, now, 30*time.Second); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestTokenWrongPSK(t *testing.T) {
	dev := [16]byte{1}
	now := time.Unix(1_700_000_000, 0)
	raw, _ := MakeToken([]byte("psk-a"), dev, now)
	tok, _ := ParseToken(raw)
	if err := tok.Verify([]byte("psk-b"), now, 30*time.Second); err == nil {
		t.Fatal("Verify with wrong PSK: want error, got nil")
	}
}

func TestTokenTamperedMAC(t *testing.T) {
	psk := []byte("psk")
	now := time.Unix(1_700_000_000, 0)
	raw, _ := MakeToken(psk, [16]byte{1}, now)
	raw[TokenSize-1] ^= 0xFF // flip a MAC bit
	tok, _ := ParseToken(raw)
	if err := tok.Verify(psk, now, 30*time.Second); err == nil {
		t.Fatal("Verify with tampered MAC: want error, got nil")
	}
}

func TestTokenStaleTimestamp(t *testing.T) {
	psk := []byte("psk")
	issued := time.Unix(1_700_000_000, 0)
	raw, _ := MakeToken(psk, [16]byte{1}, issued)
	tok, _ := ParseToken(raw)
	later := issued.Add(5 * time.Minute)
	if err := tok.Verify(psk, later, 30*time.Second); err == nil {
		t.Fatal("Verify with stale timestamp: want error, got nil")
	}
}

func TestParseTokenWrongSize(t *testing.T) {
	if _, err := ParseToken(make([]byte, TokenSize-1)); err == nil {
		t.Fatal("ParseToken(short): want error, got nil")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./authgate/ -run TestToken -v`
Expected: FAIL — build error, `undefined: MakeToken`, `undefined: TokenSize`, etc.

- [ ] **Step 3: Write the implementation**

Create `core/authgate/token.go`:
```go
// Package authgate implements the gvpn in-tunnel authentication gate: a server
// inspects the first frame of a (GOST TLS-terminated) connection and either
// admits it to the VPN data path or reverse-proxies it to a decoy origin. It
// also provides the client-side AUTH token emitter. Pure Go, no cgo.
package authgate

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

// tokenVersion is the AUTH token format version, independent of the frame
// version, so PSKs/algorithms can rotate later without a frame bump.
const tokenVersion uint8 = 1

const macSize = 32 // HMAC-SHA256 output

// TokenSize is the exact marshaled size of an AUTH token and therefore the
// exact frame payload length the gate accepts for an AUTH frame:
// version(1) + deviceID(16) + nonce(16) + timestamp(8) + mac(32).
const TokenSize = 1 + 16 + 16 + 8 + macSize // 73

// Token errors.
var (
	ErrTokenSize    = errors.New("authgate: wrong token size")
	ErrTokenVersion = errors.New("authgate: unsupported token version")
	ErrBadMAC       = errors.New("authgate: token MAC mismatch")
	ErrStale        = errors.New("authgate: token timestamp outside window")
)

// Token is the in-tunnel authentication token. The MAC binds the device, a
// random nonce, and a timestamp under the device PSK, making each token
// high-entropy, replay-bounded, and unlinkable (design §3).
type Token struct {
	Version   uint8
	DeviceID  [16]byte
	Nonce     [16]byte
	Timestamp int64
	MAC       [macSize]byte
}

// MakeToken builds a fresh AUTH token for deviceID under psk, stamped at now,
// and returns its marshaled form (use it as a frame.TypeAuth payload).
func MakeToken(psk []byte, deviceID [16]byte, now time.Time) ([]byte, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	t := Token{Version: tokenVersion, DeviceID: deviceID, Nonce: nonce, Timestamp: now.Unix()}
	t.MAC = computeMAC(psk, t)
	return t.Marshal(), nil
}

// Marshal serializes the token to its fixed TokenSize byte layout.
func (t Token) Marshal() []byte {
	b := make([]byte, TokenSize)
	b[0] = t.Version
	copy(b[1:17], t.DeviceID[:])
	copy(b[17:33], t.Nonce[:])
	binary.BigEndian.PutUint64(b[33:41], uint64(t.Timestamp))
	copy(b[41:73], t.MAC[:])
	return b
}

// ParseToken deserializes a token from a TokenSize-length payload. It does not
// verify the MAC; call Verify for that.
func ParseToken(b []byte) (Token, error) {
	if len(b) != TokenSize {
		return Token{}, ErrTokenSize
	}
	var t Token
	t.Version = b[0]
	copy(t.DeviceID[:], b[1:17])
	copy(t.Nonce[:], b[17:33])
	t.Timestamp = int64(binary.BigEndian.Uint64(b[33:41]))
	copy(t.MAC[:], b[41:73])
	return t, nil
}

// Verify recomputes the MAC under psk (constant-time compare) and checks the
// timestamp is within window of now (in either direction, tolerating clock skew).
func (t Token) Verify(psk []byte, now time.Time, window time.Duration) error {
	if t.Version != tokenVersion {
		return ErrTokenVersion
	}
	expected := computeMAC(psk, t)
	if !hmac.Equal(expected[:], t.MAC[:]) {
		return ErrBadMAC
	}
	skew := now.Sub(time.Unix(t.Timestamp, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > window {
		return ErrStale
	}
	return nil
}

// computeMAC = HMAC-SHA256(psk, version || deviceID || nonce || timestamp).
func computeMAC(psk []byte, t Token) [macSize]byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte{t.Version})
	mac.Write(t.DeviceID[:])
	mac.Write(t.Nonce[:])
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(t.Timestamp))
	mac.Write(ts[:])
	var out [macSize]byte
	copy(out[:], mac.Sum(nil))
	return out
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./authgate/ -run TestToken -v` and `... -run TestParseToken -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./authgate/`.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/authgate/token.go core/authgate/token_test.go
git commit -m "feat(authgate): AUTH token (HMAC-SHA256) construct/parse/verify

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Replay cache

**Files:**
- Create: `core/authgate/replay.go`, `core/authgate/replay_test.go`

- [ ] **Step 1: Write the failing test**

Create `core/authgate/replay_test.go`:
```go
package authgate

import (
	"sync"
	"testing"
	"time"
)

func TestReplayCacheDetectsReplay(t *testing.T) {
	c := NewReplayCache(time.Minute)
	var n [16]byte
	n[0] = 42
	if c.Seen(n) {
		t.Fatal("first Seen = true, want false")
	}
	if !c.Seen(n) {
		t.Fatal("second Seen = false, want true (replay)")
	}
}

func TestReplayCacheEvictsAfterTTL(t *testing.T) {
	c := NewReplayCache(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }
	var n [16]byte
	n[0] = 7
	c.Seen(n) // record at base
	c.now = func() time.Time { return base.Add(2 * time.Minute) } // past ttl
	if c.Seen(n) {
		t.Fatal("Seen after eviction = true, want false")
	}
}

func TestReplayCacheConcurrent(t *testing.T) {
	c := NewReplayCache(time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var n [16]byte
			n[0] = byte(i)
			c.Seen(n)
		}(i)
	}
	wg.Wait()
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./authgate/ -run TestReplay -v`
Expected: FAIL — `undefined: NewReplayCache`.

- [ ] **Step 3: Write the implementation**

Create `core/authgate/replay.go`:
```go
package authgate

import (
	"sync"
	"time"
)

// ReplayCache remembers recently-seen nonces so a captured AUTH token cannot be
// replayed within its validity window. Safe for concurrent use.
//
// Eviction is O(n) per call, which is fine at phase-1 scale (a nonce lives for
// ttl; at ~50 handshakes/s and a 60s ttl that is a few thousand entries). A
// bucketed/expiry-heap variant is a later optimization if profiling demands it.
type ReplayCache struct {
	ttl  time.Duration
	now  func() time.Time
	mu   sync.Mutex
	seen map[[16]byte]time.Time
}

// NewReplayCache returns a cache that remembers nonces for ttl.
func NewReplayCache(ttl time.Duration) *ReplayCache {
	return &ReplayCache{ttl: ttl, now: time.Now, seen: make(map[[16]byte]time.Time)}
}

// Seen records nonce and reports whether it had already been seen within ttl. A
// return of true means the token is a replay and must be rejected.
func (c *ReplayCache) Seen(nonce [16]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.evictLocked(now)
	if ts, ok := c.seen[nonce]; ok && now.Sub(ts) <= c.ttl {
		return true
	}
	c.seen[nonce] = now
	return false
}

func (c *ReplayCache) evictLocked(now time.Time) {
	for k, ts := range c.seen {
		if now.Sub(ts) > c.ttl {
			delete(c.seen, k)
		}
	}
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./authgate/ -run TestReplay -v`
Expected: PASS (including under `-race`). Also `/home/goodvin/.local/go/bin/go vet ./authgate/`.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/authgate/replay.go core/authgate/replay_test.go
git commit -m "feat(authgate): nonce replay cache with TTL eviction

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Device store

**Files:**
- Create: `core/authgate/registry.go`, `core/authgate/registry_test.go`

- [ ] **Step 1: Write the failing test**

Create `core/authgate/registry_test.go`:
```go
package authgate

import (
	"bytes"
	"testing"
)

func TestMapStoreLookup(t *testing.T) {
	dev := [16]byte{1, 2, 3}
	store := NewMapStore(map[[16]byte][]byte{dev: []byte("psk")})

	psk, ok := store.Lookup(dev)
	if !ok {
		t.Fatal("Lookup registered device: ok = false")
	}
	if !bytes.Equal(psk, []byte("psk")) {
		t.Fatalf("psk = %q, want %q", psk, "psk")
	}
	if _, ok := store.Lookup([16]byte{9}); ok {
		t.Fatal("Lookup unknown device: ok = true")
	}
}

func TestMapStoreNil(t *testing.T) {
	store := NewMapStore(nil)
	if _, ok := store.Lookup([16]byte{1}); ok {
		t.Fatal("Lookup on empty store: ok = true")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./authgate/ -run TestMapStore -v`
Expected: FAIL — `undefined: NewMapStore`.

- [ ] **Step 3: Write the implementation**

Create `core/authgate/registry.go`:
```go
package authgate

// DeviceStore resolves a DeviceID to its AUTH pre-shared key. The gate uses it
// to find the PSK for the device a connection claims to be. Implementations
// must be safe for concurrent use by the gate.
type DeviceStore interface {
	// Lookup returns the PSK for deviceID and whether it is registered.
	Lookup(deviceID [16]byte) (psk []byte, ok bool)
}

// MapStore is an in-memory DeviceStore for phase-1 and tests. It is read-only
// after construction, so it needs no locking.
type MapStore struct {
	devices map[[16]byte][]byte
}

// NewMapStore builds a MapStore from a deviceID->PSK map (nil is allowed and
// yields an empty store). The caller must not mutate devices afterward.
func NewMapStore(devices map[[16]byte][]byte) *MapStore {
	if devices == nil {
		devices = map[[16]byte][]byte{}
	}
	return &MapStore{devices: devices}
}

// Lookup implements DeviceStore.
func (s *MapStore) Lookup(deviceID [16]byte) ([]byte, bool) {
	psk, ok := s.devices[deviceID]
	return psk, ok
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./authgate/ -run TestMapStore -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./authgate/`.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/authgate/registry.go core/authgate/registry_test.go
git commit -m "feat(authgate): DeviceStore interface + in-memory MapStore

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Decoy reverse-proxy

**Files:**
- Create: `core/authgate/decoy.go`, `core/authgate/decoy_test.go`

- [ ] **Step 1: Write the failing test**

Create `core/authgate/decoy_test.go`:
```go
package authgate

import (
	"bufio"
	"bytes"
	"net"
	"testing"
	"time"
)

func TestTCPDecoyReplaysPrefixAndRelays(t *testing.T) {
	// Fake decoy origin: read one request line, reply with a canned page.
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen origin: %v", err)
	}
	defer origin.Close()

	gotLine := make(chan string, 1)
	go func() {
		c, err := origin.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		gotLine <- line
		c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nDECOY"))
	}()

	client, server := net.Pipe()
	defer client.Close()

	decoy := TCPDecoy{Origin: origin.Addr().String()}
	go decoy.Handle(server, []byte("GET / HTTP/1.1\r\n"))

	select {
	case line := <-gotLine:
		if line != "GET / HTTP/1.1\r\n" {
			t.Fatalf("origin got %q, want the replayed prefix", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("origin never received the replayed prefix")
	}

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("client read relayed response: %v", err)
	}
	if !bytes.Contains(buf[:n], []byte("DECOY")) {
		t.Fatalf("client got %q, want the decoy page relayed back", buf[:n])
	}
}

func TestTCPDecoyDialError(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	// 127.0.0.1:1 should refuse; Handle must return an error and close server.
	decoy := TCPDecoy{Origin: "127.0.0.1:1", DialTimeout: time.Second}
	if err := decoy.Handle(server, nil); err == nil {
		t.Fatal("Handle to dead origin: want error, got nil")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./authgate/ -run TestTCPDecoy -v`
Expected: FAIL — `undefined: TCPDecoy`.

- [ ] **Step 3: Write the implementation**

Create `core/authgate/decoy.go`:
```go
package authgate

import (
	"fmt"
	"io"
	"net"
	"time"
)

// Decoy handles connections that fail authentication. The censorship-resistance
// design (§3) requires serving these as a real website rather than dropping
// them, so an active prober sees an ordinary HTTPS origin.
type Decoy interface {
	// Handle takes ownership of client and must close it. prefix is the bytes
	// already read from client during the auth attempt; they are replayed to the
	// origin first so the proxied request is intact.
	Handle(client net.Conn, prefix []byte) error
}

// TCPDecoy transparently reverse-proxies the (already TLS-terminated)
// connection to a plain-TCP decoy origin, e.g. a local web server serving a
// plausible site matching the server's GOST cert domain.
type TCPDecoy struct {
	Origin      string        // host:port of the decoy origin
	DialTimeout time.Duration // <=0 => 5s
}

func (d TCPDecoy) dialTimeout() time.Duration {
	if d.DialTimeout <= 0 {
		return 5 * time.Second
	}
	return d.DialTimeout
}

// Handle implements Decoy.
func (d TCPDecoy) Handle(client net.Conn, prefix []byte) error {
	defer client.Close()

	origin, err := net.DialTimeout("tcp", d.Origin, d.dialTimeout())
	if err != nil {
		return fmt.Errorf("authgate: dial decoy %q: %w", d.Origin, err)
	}
	defer origin.Close()

	if len(prefix) > 0 {
		if _, err := origin.Write(prefix); err != nil {
			return fmt.Errorf("authgate: replay prefix to decoy: %w", err)
		}
	}

	// Splice both directions. Return once either ends; the deferred Close calls
	// unblock the other io.Copy (errc is buffered so neither goroutine leaks).
	errc := make(chan error, 2)
	go func() { _, e := io.Copy(origin, client); errc <- e }()
	go func() { _, e := io.Copy(client, origin); errc <- e }()
	<-errc
	return nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./authgate/ -run TestTCPDecoy -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/authgate/decoy.go core/authgate/decoy_test.go
git commit -m "feat(authgate): TCPDecoy reverse-proxy with prefix replay

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: The gate (Handle)

**Files:**
- Create: `core/authgate/gate.go`, `core/authgate/gate_test.go`

- [ ] **Step 1: Write the failing test**

Create `core/authgate/gate_test.go`:
```go
package authgate

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/frame"
)

func fixedClock(unix int64) func() time.Time {
	return func() time.Time { return time.Unix(unix, 0) }
}

// fakeDecoy records that it was called and the prefix it received.
type fakeDecoy struct {
	mu     sync.Mutex
	called bool
	prefix []byte
}

func (f *fakeDecoy) Handle(client net.Conn, prefix []byte) error {
	f.mu.Lock()
	f.called = true
	f.prefix = append([]byte(nil), prefix...)
	f.mu.Unlock()
	client.Close()
	return nil
}

func TestGateAuthenticatedPath(t *testing.T) {
	dev := [16]byte{1, 2, 3, 4}
	psk := []byte("device-psk")
	g := NewGate(NewMapStore(map[[16]byte][]byte{dev: psk}), nil)
	const now = int64(1_700_000_000)
	g.now = fixedClock(now)

	client, server := net.Pipe()
	defer client.Close()
	go func() {
		tok, _ := MakeToken(psk, dev, time.Unix(now, 0))
		frame.WriteFrame(client, frame.TypeAuth, tok)
		frame.WriteFrame(client, frame.TypeData, []byte("packet"))
	}()

	res, err := g.Handle(server)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !res.Authenticated || res.DeviceID != dev {
		t.Fatalf("auth=%v dev=%x, want true %x", res.Authenticated, res.DeviceID, dev)
	}
	// The gate must consume only the AUTH frame; the DATA frame follows.
	typ, payload, err := frame.ReadFrame(res.Conn)
	if err != nil {
		t.Fatalf("ReadFrame after auth: %v", err)
	}
	if typ != frame.TypeData || string(payload) != "packet" {
		t.Fatalf("next frame = (%d,%q), want (DATA,%q)", typ, payload, "packet")
	}
	res.Conn.Close()
}

func TestGateDecoyOnHTTP(t *testing.T) {
	fd := &fakeDecoy{}
	g := NewGate(NewMapStore(nil), fd)

	client, server := net.Pipe()
	defer client.Close()
	sent := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	go func() {
		client.Write(sent)
		client.Close()
	}()

	res, err := g.Handle(server)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if res.Authenticated {
		t.Fatal("HTTP request authenticated; want decoy")
	}
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.called {
		t.Fatal("decoy not invoked for HTTP request")
	}
	if len(fd.prefix) == 0 || !bytes.HasPrefix(sent, fd.prefix) {
		t.Fatalf("decoy prefix %q must be a leading slice of the client bytes", fd.prefix)
	}
}

func TestGateDecoyOnUnknownDevice(t *testing.T) {
	dev := [16]byte{2}
	psk := []byte("psk")
	fd := &fakeDecoy{}
	g := NewGate(NewMapStore(nil), fd) // device not registered
	const now = int64(1_700_000_000)
	g.now = fixedClock(now)

	client, server := net.Pipe()
	defer client.Close()
	go func() {
		tok, _ := MakeToken(psk, dev, time.Unix(now, 0))
		frame.WriteFrame(client, frame.TypeAuth, tok)
		client.Close()
	}()

	res, _ := g.Handle(server)
	if res.Authenticated {
		t.Fatal("unknown device authenticated; want decoy")
	}
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.called {
		t.Fatal("decoy not invoked for unknown device")
	}
}

func TestGateRejectsReplay(t *testing.T) {
	dev := [16]byte{5}
	psk := []byte("psk")
	fd := &fakeDecoy{}
	g := NewGate(NewMapStore(map[[16]byte][]byte{dev: psk}), fd)
	const now = int64(1_700_000_000)
	g.now = fixedClock(now)
	tok, _ := MakeToken(psk, dev, time.Unix(now, 0))

	// First use authenticates.
	c1, s1 := net.Pipe()
	go func() { frame.WriteFrame(c1, frame.TypeAuth, tok) }()
	res1, _ := g.Handle(s1)
	if !res1.Authenticated {
		t.Fatal("first use not authenticated")
	}
	c1.Close()
	res1.Conn.Close()

	// Same token again must fall to decoy.
	c2, s2 := net.Pipe()
	defer c2.Close()
	go func() {
		frame.WriteFrame(c2, frame.TypeAuth, tok)
		c2.Close()
	}()
	res2, _ := g.Handle(s2)
	if res2.Authenticated {
		t.Fatal("replayed token authenticated; want decoy")
	}
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.called {
		t.Fatal("decoy not invoked on replay")
	}
}

func TestGateNilDecoyClosesConn(t *testing.T) {
	g := NewGate(NewMapStore(nil), nil)
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		client.Write([]byte("garbage-bytes-not-a-frame"))
		client.Close()
	}()
	res, err := g.Handle(server)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if res.Authenticated {
		t.Fatal("garbage authenticated; want decoy/close")
	}
	// server should now be closed by the gate: a write must fail.
	if _, err := server.Write([]byte("x")); err == nil {
		t.Fatal("server conn still open after nil-decoy decoy path")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./authgate/ -run TestGate -v`
Expected: FAIL — `undefined: NewGate`, `undefined: Result`.

- [ ] **Step 3: Write the implementation**

Create `core/authgate/gate.go`:
```go
package authgate

import (
	"io"
	"net"
	"time"

	"github.com/g00dvin/gvpn/core/frame"
)

// Default gate timings.
const (
	defaultWindow      = 30 * time.Second
	defaultReadTimeout = 10 * time.Second
)

// Result is the outcome of Gate.Handle.
type Result struct {
	// Authenticated is true when the first frame was a valid, fresh AUTH token.
	Authenticated bool
	// DeviceID is the verified device; set only when Authenticated.
	DeviceID [16]byte
	// Conn is the connection positioned immediately after the AUTH frame, ready
	// for the VPN data path. Set only when Authenticated; otherwise the gate has
	// already handed the connection to the decoy (or closed it) and Conn is nil.
	Conn net.Conn
}

// Gate is the server-side in-tunnel authentication gate. It inspects the first
// frame of an already-TLS-terminated connection: a valid AUTH token switches the
// connection to the VPN data path; anything else is reverse-proxied to the decoy
// (design §3).
type Gate struct {
	store       DeviceStore
	decoy       Decoy
	replay      *ReplayCache
	window      time.Duration
	readTimeout time.Duration
	now         func() time.Time
}

// NewGate builds a Gate. store resolves device PSKs; decoy receives
// unauthenticated connections (nil => they are simply closed). Defaults: 30s
// token window, 10s first-frame read timeout, replay TTL = 2*window.
func NewGate(store DeviceStore, decoy Decoy) *Gate {
	return &Gate{
		store:       store,
		decoy:       decoy,
		replay:      NewReplayCache(2 * defaultWindow),
		window:      defaultWindow,
		readTimeout: defaultReadTimeout,
		now:         time.Now,
	}
}

// Handle inspects conn's first frame and decides VPN-vs-decoy. On the
// authenticated path it returns Result{Authenticated:true, Conn:conn} (caller
// owns conn). On the decoy path it proxies/closes conn and returns
// Result{Authenticated:false}; any decoy error is returned for logging but conn
// is consumed either way.
func (g *Gate) Handle(conn net.Conn) (Result, error) {
	_ = conn.SetReadDeadline(g.now().Add(g.readTimeout))
	rec := &recordingReader{r: conn}

	hdr := make([]byte, frame.HeaderSize)
	if _, err := io.ReadFull(rec, hdr); err != nil {
		return g.toDecoy(conn, rec.buf)
	}
	h, err := frame.ParseHeader(hdr)
	// Reject on the header alone before reading any payload: strict version/type
	// and an exact AUTH length keep a prober from steering us into a large read.
	if err != nil || h.Version != frame.Version1 || h.Type != frame.TypeAuth || int(h.Length) != TokenSize {
		return g.toDecoy(conn, rec.buf)
	}
	payload := make([]byte, TokenSize)
	if _, err := io.ReadFull(rec, payload); err != nil {
		return g.toDecoy(conn, rec.buf)
	}
	tok, err := ParseToken(payload)
	if err != nil {
		return g.toDecoy(conn, rec.buf)
	}
	psk, ok := g.store.Lookup(tok.DeviceID)
	if !ok {
		return g.toDecoy(conn, rec.buf)
	}
	if err := tok.Verify(psk, g.now(), g.window); err != nil {
		return g.toDecoy(conn, rec.buf)
	}
	if g.replay.Seen(tok.Nonce) {
		return g.toDecoy(conn, rec.buf)
	}

	_ = conn.SetReadDeadline(time.Time{}) // hand a clean conn to the data path
	return Result{Authenticated: true, DeviceID: tok.DeviceID, Conn: conn}, nil
}

func (g *Gate) toDecoy(conn net.Conn, prefix []byte) (Result, error) {
	_ = conn.SetReadDeadline(time.Time{})
	if g.decoy == nil {
		conn.Close()
		return Result{Authenticated: false}, nil
	}
	err := g.decoy.Handle(conn, prefix)
	return Result{Authenticated: false}, err
}

// recordingReader records every byte read so the gate can replay the consumed
// prefix to the decoy when authentication fails.
type recordingReader struct {
	r   io.Reader
	buf []byte
}

func (rr *recordingReader) Read(p []byte) (int, error) {
	n, err := rr.r.Read(p)
	if n > 0 {
		rr.buf = append(rr.buf, p[:n]...)
	}
	return n, err
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./authgate/ -run TestGate -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/authgate/gate.go core/authgate/gate_test.go
git commit -m "feat(authgate): the AUTH gate (first-frame inspect, VPN-vs-decoy)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Client AUTH emitter + end-to-end

**Files:**
- Create: `core/authgate/client.go`, `core/authgate/client_test.go`

- [ ] **Step 1: Write the failing test**

Create `core/authgate/client_test.go`:
```go
package authgate

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/frame"
)

// TestEndToEndAuthenticated runs WriteAuth (client) against Gate.Handle (server)
// over a real TCP loopback, then confirms a following DATA frame reaches the
// data path.
func TestEndToEndAuthenticated(t *testing.T) {
	dev := [16]byte{9, 8, 7}
	psk := []byte("e2e-psk")
	g := NewGate(NewMapStore(map[[16]byte][]byte{dev: psk}), nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type out struct {
		r   Result
		err error
	}
	outc := make(chan out, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			outc <- out{err: err}
			return
		}
		r, err := g.Handle(conn)
		outc <- out{r: r, err: err}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := WriteAuth(conn, psk, dev); err != nil {
		t.Fatalf("WriteAuth: %v", err)
	}
	if err := frame.WriteFrame(conn, frame.TypeData, []byte("hello")); err != nil {
		t.Fatalf("WriteFrame data: %v", err)
	}

	got := <-outc
	if got.err != nil {
		t.Fatalf("gate: %v", got.err)
	}
	if !got.r.Authenticated || got.r.DeviceID != dev {
		t.Fatalf("auth=%v dev=%x", got.r.Authenticated, got.r.DeviceID)
	}
	got.r.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, payload, err := frame.ReadFrame(got.r.Conn)
	if err != nil {
		t.Fatalf("read data frame: %v", err)
	}
	if typ != frame.TypeData || string(payload) != "hello" {
		t.Fatalf("data frame = (%d,%q)", typ, payload)
	}
	got.r.Conn.Close()
}

// TestEndToEndDecoy confirms an unauthenticated client is served the decoy page.
func TestEndToEndDecoy(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen origin: %v", err)
	}
	defer origin.Close()
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				c.Read(buf)
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nDECOY"))
			}(c)
		}
	}()

	g := NewGate(NewMapStore(nil), TCPDecoy{Origin: origin.Addr().String()})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		g.Handle(conn)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.Write([]byte("GET / HTTP/1.1\r\nHost: gvpn\r\n\r\n"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read decoy response: %v", err)
	}
	if !bytes.Contains(buf[:n], []byte("DECOY")) {
		t.Fatalf("got %q, want the decoy page", buf[:n])
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./authgate/ -run TestEndToEnd -v`
Expected: FAIL — `undefined: WriteAuth`.

- [ ] **Step 3: Write the implementation**

Create `core/authgate/client.go`:
```go
package authgate

import (
	"net"
	"time"

	"github.com/g00dvin/gvpn/core/frame"
)

// WriteAuth sends the in-tunnel AUTH frame as the first frame on conn, using the
// device PSK and ID. The client must call this immediately after each (re)connect
// and GOST TLS handshake, before any DATA frame (design §3, §5).
func WriteAuth(conn net.Conn, psk []byte, deviceID [16]byte) error {
	tok, err := MakeToken(psk, deviceID, time.Now())
	if err != nil {
		return err
	}
	return frame.WriteFrame(conn, frame.TypeAuth, tok)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./authgate/ -v`
Expected: PASS (all authgate tests).

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/authgate/client.go core/authgate/client_test.go
git commit -m "feat(authgate): client WriteAuth + end-to-end gate tests

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: Full verification + PR

**Files:** none (verification + PR only).

- [ ] **Step 1: Full package suite under race + vet**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test -race ./authgate/
/home/goodvin/.local/go/bin/go vet ./authgate/
```
Expected: PASS, vet clean.

- [ ] **Step 2: Whole-repo build sanity (cgo on, includes gosttls)**

Run:
```bash
cd /home/goodvin/git/gvpn/core
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go build ./...
```
Expected: builds (gosttls compiles via the engine toolchain). If the gost engine/libs are unavailable in the execution environment, this step may fail to *link* gosttls — that is acceptable here as long as `./authgate/` tests pass; note it and continue. (CI already provisions the engine.)

- [ ] **Step 3: Push and open PR** (trivial / `gh` — Haiku)

```bash
cd /home/goodvin/git/gvpn
git push -u origin feat/auth-gate
gh pr create --base main --head feat/auth-gate \
  --title "In-tunnel AUTH gate + decoy fallback" \
  --body "Implements design §3: server-side first-frame AUTH gate over GOST TLS. Valid HMAC-SHA256 AUTH token (replay-bounded, per-device PSK) -> VPN data path; bad token / HTTP / garbage / replay -> transparent reverse-proxy to a decoy origin. Adds client WriteAuth emitter. Pure Go, tested with -race (token, replay, store, decoy, gate, end-to-end).

Out of scope (later plans): wiring the gate into the server's TLS listener + wireguard-go data path, sending AUTH on each reconnect through the transport adapter, SESSION_BIND/session manager.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

---

## Self-Review

**Spec coverage (design §3, §4, §5):**
- First-frame AUTH gate, VPN-vs-decoy → Tasks 5 (gate) + 1 (token) + 6 (e2e).
- AUTH token = `HMAC(PSK, nonce||timestamp)`, high-entropy / replay-bounded / unlinkable → Task 1 (HMAC-SHA256 over version||deviceID||nonce||timestamp) + Task 2 (replay cache).
- Decoy reverse-proxy to a real origin for probers → Task 4 (TCPDecoy) + Task 6 (e2e decoy).
- Per-device PSK lookup (provisioning model, §6) → Task 3 (DeviceStore/MapStore).
- Client sends AUTH first, including after reconnect (§5) → Task 6 (WriteAuth). *Wiring* WriteAuth into the reconnecting transport's re-dial sequence is explicitly deferred to a later plan (noted in the PR body) — this plan delivers the building block and proves it end-to-end.
- Out of scope here (later plans): server TLS listener wiring, wireguard-go data path, SESSION_BIND/session manager. Stated in the PR body and design.

**Placeholder scan:** none — every code step contains complete, compilable code.

**Type consistency:** `TokenSize` (const, used by Task 1 token + Task 5 gate length check), `Token{Version,DeviceID[16],Nonce[16],Timestamp,MAC[32]}`, `MakeToken(psk,[16]byte,time.Time)([]byte,error)`, `ParseToken([]byte)(Token,error)`, `Token.Verify(psk,now,window)error`, `NewReplayCache(ttl)*ReplayCache` + `Seen([16]byte)bool` + settable `now`, `DeviceStore.Lookup([16]byte)([]byte,bool)` + `NewMapStore(map[[16]byte][]byte)`, `Decoy.Handle(net.Conn,[]byte)error` + `TCPDecoy{Origin,DialTimeout}`, `NewGate(DeviceStore,Decoy)*Gate` + settable `now` + `Handle(net.Conn)(Result,error)`, `Result{Authenticated,DeviceID[16],Conn}`, `WriteAuth(net.Conn,psk,[16]byte)error`. The gate's strict length check uses `TokenSize` from Task 1 (consistent). Frame APIs match `core/frame` exactly (verified against source).

**Security note for the Opus security review (Task 7 controller step):** confirm (1) `hmac.Equal` constant-time compare is used (no `==` on MACs), (2) the gate never reads more than `TokenSize` on the auth path before validating, (3) the first-frame read deadline bounds prober stalls, (4) the decoy path replays the exact consumed prefix so no client bytes are lost or duplicated, (5) no PSK/token material is logged.
```
