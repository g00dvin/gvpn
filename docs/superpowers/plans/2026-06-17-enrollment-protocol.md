# Enrollment Protocol Primitives Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Per-task model assignment (standing rule):** **Sonnet** subagent implements each code task; **Opus** (controller) manages tasks and reviews each diff, and dispatches a fresh **Opus** subagent for the final review; **Haiku** subagent does the `gh` push + PR.

**Goal:** Add the wire-level primitives for dynamic device enrollment — an AUTH-token `kind` byte (DEVICE vs ENROLL), a user-PSK lookup on the gate, a gate result that signals the enroll path + user id, and a typed ENROLL request/response exchange with client+server helpers — without wiring them into the server data path (that is Plan 11).

**Architecture:** The merged in-tunnel AUTH token (`core/authgate/token.go`) gains a 1-byte `Kind` discriminator bound by the HMAC; the same 16-byte id field carries a `DeviceID` (KindDevice) or a user id (KindEnroll). `authgate.DeviceStore` grows `EnrollLookup(userID)`; `provision.FileStore` and the test `MapStore` implement it. `Gate.Handle` branches on kind and reports `Result.Kind` + `Result.UserID`. A new `core/enroll` package defines the post-gate `Request{WGPublic}` / `Response{DeviceID,TunnelIP,DevicePSK}` messages carried in two new `frame` types, plus client (`Exchange`) and server (`ReadRequest`/`WriteResponse`) helpers; `authgate.WriteEnrollAuth` emits the KindEnroll AUTH frame. Everything stays pure Go (cgo-free) and keeps `main` green at every commit.

**Tech Stack:** Go 1.24, stdlib only. Toolchain `/home/goodvin/.local/go/bin/go`. Module `github.com/g00dvin/gvpn/core`.

**Design reference:** `docs/superpowers/specs/2026-06-16-user-identity-enrollment-admin-design.md` §6 (token kind), §7 (dynamic enrollment), §3 (gate/decoy).

---

## Conventions

- Toolchain: `/home/goodvin/.local/go/bin/go`. Run the touched packages with `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./authgate/ ./frame/ ./enroll/ ./provision/`.
- Branch `feat/enrollment-protocol` off `main` (already created; this plan doc is committed there).
- Commits end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Pre-existing untracked artifacts must NOT be committed; `.gitignore` already covers `gvpn-provision`, `go.work.sum`, `*.gvpn`, `registry.json`. Only `git add` the files each task names.
- **Breaking change, no migration:** the AUTH token wire format changes (adds a kind byte, `TokenSize` 73 → 74). Client and server are released together; there are no deployed peers to migrate. Do not write back-compat code.

## Decisions locked for this plan

- **Token layout (74 bytes):** `version(1) || kind(1) || id(16) || nonce(16) || timestamp(8) || mac(32)`. The HMAC covers `version || kind || id || nonce || timestamp`, so the kind byte cannot be flipped without invalidating the MAC.
- **Field reuse:** keep the struct field name `Token.DeviceID` (the existing tests reference it); it carries a device id for KindDevice and a user id for KindEnroll. The gate maps it to `Result.DeviceID` or `Result.UserID` by kind.
- **Store method name:** the interface method is `EnrollLookup(userID [16]byte) ([]byte, bool)` (symmetry with `Lookup`). `provision.FileStore` already has `EnrollPSK` with the same signature; add a one-line `EnrollLookup` that delegates to it (keeps Plan 9's public API intact).
- **Enroll exchange transport:** two dedicated frame types — `TypeEnrollRequest = 5`, `TypeEnrollResponse = 6` — not an overloaded `TypeControl`. The messages live in a new `core/enroll` package (cgo-free) so Plan 11 can call it from the multiplexed server.
- **Response layout:** `deviceID(16) || pskLen(1) || psk(pskLen) || tunnelIP(rest as UTF-8)` — self-describing, not coupled to `provision.authPSKSize`.
- **Out of scope (Plan 11+):** wiring the enroll path into `core/server`, runtime `AddDevice`+`AddPeer`, the multiplexed engine, guardrail enforcement (cap/open-closed). This plan ships primitives + unit tests only.

## File structure

```
core/authgate/token.go        + Kind field, KindDevice/KindEnroll, MakeEnrollToken, 74-byte layout   (MODIFY)
core/authgate/token_test.go   + enroll-token + kind-binding tests                                     (MODIFY)
core/authgate/registry.go     DeviceStore += EnrollLookup; MapStore enroll map + NewMapStoreWithEnroll(MODIFY)
core/authgate/registry_test.go+ EnrollLookup tests                                                    (MODIFY)
core/authgate/gate.go         Result += Kind/UserID; Handle branches on kind                          (MODIFY)
core/authgate/gate_test.go    + enroll-path / unknown-user / cross-path tests                          (MODIFY)
core/authgate/client.go       + WriteEnrollAuth                                                        (MODIFY)
core/authgate/client_test.go  + WriteEnrollAuth-admitted-by-gate test                                 (MODIFY)
core/provision/store.go       + FileStore.EnrollLookup (delegates to EnrollPSK)                        (MODIFY)
core/provision/store_test.go  + interface assertion + EnrollLookup test                               (MODIFY)
core/frame/frame.go           + TypeEnrollRequest, TypeEnrollResponse                                  (MODIFY)
core/frame/frame_test.go      + enroll-frame-types round-trip                                          (MODIFY)
core/enroll/enroll.go         Request/Response marshal/parse                                           (CREATE)
core/enroll/enroll_test.go    codec round-trip + reject-short                                          (CREATE)
core/enroll/exchange.go       Exchange (client) / ReadRequest / WriteResponse (server)                 (CREATE)
core/enroll/exchange_test.go  net.Pipe round-trip                                                      (CREATE)
```

---

## Task 1: AUTH token gains a `kind` byte

**Files:** Modify `core/authgate/token.go`, `core/authgate/token_test.go`.

The existing token tests reference `TokenSize` (a const that auto-updates) and `tok.DeviceID` (field retained) and flip the last byte (the MAC), so they keep passing. We add the kind field, `MakeEnrollToken`, and new tests.

- [ ] **Step 1: Write the failing tests (append to `core/authgate/token_test.go`)**

```go
func TestEnrollTokenRoundTrip(t *testing.T) {
	psk := []byte("enroll-psk")
	uid := [16]byte{9, 9, 9}
	now := time.Unix(1_700_000_000, 0)
	raw, err := MakeEnrollToken(psk, uid, now)
	if err != nil {
		t.Fatalf("MakeEnrollToken: %v", err)
	}
	if len(raw) != TokenSize {
		t.Fatalf("token size = %d, want %d", len(raw), TokenSize)
	}
	tok, err := ParseToken(raw)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if tok.Kind != KindEnroll {
		t.Fatalf("Kind = %d, want KindEnroll", tok.Kind)
	}
	if tok.DeviceID != uid {
		t.Fatalf("id = %x, want %x", tok.DeviceID, uid)
	}
	if err := tok.Verify(psk, now, 30*time.Second); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestMakeTokenIsDeviceKind(t *testing.T) {
	raw, _ := MakeToken([]byte("psk"), [16]byte{1}, time.Unix(1_700_000_000, 0))
	tok, _ := ParseToken(raw)
	if tok.Kind != KindDevice {
		t.Fatalf("MakeToken kind = %d, want KindDevice", tok.Kind)
	}
}

func TestTokenKindIsBoundByMAC(t *testing.T) {
	// Flipping the kind byte of a device token must invalidate the MAC.
	psk := []byte("psk")
	now := time.Unix(1_700_000_000, 0)
	raw, _ := MakeToken(psk, [16]byte{1}, now)
	raw[1] = KindEnroll // tamper the kind byte
	tok, _ := ParseToken(raw)
	if err := tok.Verify(psk, now, 30*time.Second); err == nil {
		t.Fatal("kind tamper accepted; MAC must bind kind")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./authgate/ -run 'TestEnrollToken|TestMakeTokenIsDeviceKind|TestTokenKind' -v`
Expected: build error — `undefined: MakeEnrollToken` / `undefined: KindEnroll` / `tok.Kind` undefined.

- [ ] **Step 3: Replace `core/authgate/token.go` with:**

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

// Token kinds select the gate path (design §6). The 16-byte id field is a
// DeviceID for KindDevice and a user id for KindEnroll.
const (
	KindDevice uint8 = 0
	KindEnroll uint8 = 1
)

// TokenSize is the exact marshaled size of an AUTH token and therefore the
// exact frame payload length the gate accepts for an AUTH frame:
// version(1) + kind(1) + id(16) + nonce(16) + timestamp(8) + mac(32).
const TokenSize = 1 + 1 + 16 + 16 + 8 + macSize // 74

// Token errors.
var (
	ErrTokenSize    = errors.New("authgate: wrong token size")
	ErrTokenVersion = errors.New("authgate: unsupported token version")
	ErrBadMAC       = errors.New("authgate: token MAC mismatch")
	ErrStale        = errors.New("authgate: token timestamp outside window")
)

// Token is the in-tunnel authentication token. Kind selects the gate path; the
// DeviceID field carries a device id (KindDevice) or a user id (KindEnroll). The
// MAC binds the kind, the id, a random nonce, and a timestamp under the relevant
// PSK, making each token high-entropy, replay-bounded, and unlinkable (§3).
type Token struct {
	Version   uint8
	Kind      uint8
	DeviceID  [16]byte
	Nonce     [16]byte
	Timestamp int64
	MAC       [macSize]byte
}

// MakeToken builds a fresh KindDevice AUTH token for deviceID under the
// per-device psk, stamped at now, and returns its marshaled form.
func MakeToken(psk []byte, deviceID [16]byte, now time.Time) ([]byte, error) {
	return makeToken(psk, KindDevice, deviceID, now)
}

// MakeEnrollToken builds a fresh KindEnroll AUTH token for userID under the
// user's enrollment psk. A new device sends it to bootstrap enrollment (§7).
func MakeEnrollToken(psk []byte, userID [16]byte, now time.Time) ([]byte, error) {
	return makeToken(psk, KindEnroll, userID, now)
}

func makeToken(psk []byte, kind uint8, id [16]byte, now time.Time) ([]byte, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	t := Token{Version: tokenVersion, Kind: kind, DeviceID: id, Nonce: nonce, Timestamp: now.Unix()}
	t.MAC = computeMAC(psk, t)
	return t.Marshal(), nil
}

// Marshal serializes the token to its fixed TokenSize byte layout.
func (t Token) Marshal() []byte {
	b := make([]byte, TokenSize)
	b[0] = t.Version
	b[1] = t.Kind
	copy(b[2:18], t.DeviceID[:])
	copy(b[18:34], t.Nonce[:])
	binary.BigEndian.PutUint64(b[34:42], uint64(t.Timestamp))
	copy(b[42:74], t.MAC[:])
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
	t.Kind = b[1]
	copy(t.DeviceID[:], b[2:18])
	copy(t.Nonce[:], b[18:34])
	t.Timestamp = int64(binary.BigEndian.Uint64(b[34:42]))
	copy(t.MAC[:], b[42:74])
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

// computeMAC = HMAC-SHA256(psk, version || kind || id || nonce || timestamp).
func computeMAC(psk []byte, t Token) [macSize]byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte{t.Version, t.Kind})
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

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./authgate/ -v 2>&1 | tail -40`
Expected: PASS, including the existing token/gate/client tests (the gate still compiles — it reads `tok.DeviceID` and the const `TokenSize`). Also `/home/goodvin/.local/go/bin/go vet ./authgate/`.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/authgate/token.go core/authgate/token_test.go
git commit -m "feat(authgate): AUTH token kind byte (device vs enroll)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: DeviceStore gains an enrollment lookup

**Files:** Modify `core/authgate/registry.go`, `core/authgate/registry_test.go`, `core/provision/store.go`, `core/provision/store_test.go`.

`DeviceStore` grows `EnrollLookup`. The two implementers — the test `MapStore` and `provision.FileStore` — gain it. `FileStore.EnrollLookup` delegates to the existing `EnrollPSK` (Plan 9). `core/server` keeps building because it passes a `*provision.FileStore`, which now satisfies the larger interface.

- [ ] **Step 1: Write the failing tests**

Append to `core/authgate/registry_test.go`:
```go
func TestMapStoreEnrollLookup(t *testing.T) {
	uid := [16]byte{7, 7, 7}
	store := NewMapStoreWithEnroll(nil, map[[16]byte][]byte{uid: []byte("enroll")})
	psk, ok := store.EnrollLookup(uid)
	if !ok || !bytes.Equal(psk, []byte("enroll")) {
		t.Fatalf("EnrollLookup = %q,%v want enroll,true", psk, ok)
	}
	if _, ok := store.EnrollLookup([16]byte{8}); ok {
		t.Fatal("EnrollLookup unknown user: ok = true")
	}
	// A plain NewMapStore has no enrollment users.
	if _, ok := NewMapStore(nil).EnrollLookup(uid); ok {
		t.Fatal("NewMapStore should have no enroll users")
	}
}
```

Append to `core/provision/store_test.go` (and add `"github.com/g00dvin/gvpn/core/authgate"` to that file's imports):
```go
// FileStore must satisfy the gate's DeviceStore (device + enroll lookups).
var _ authgate.DeviceStore = (*FileStore)(nil)

func TestFileStoreEnrollLookupMatchesEnrollPSK(t *testing.T) {
	fs, _ := newTestStore(t)
	u, enrollPSK, err := fs.AddUser("carol")
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	uid, _ := ParseDeviceID(u.ID)
	got, ok := fs.EnrollLookup(uid)
	if !ok || string(got) != string(enrollPSK) {
		t.Fatalf("EnrollLookup = %q,%v want the minted secret", got, ok)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./authgate/ ./provision/ -run 'EnrollLookup' -v`
Expected: build errors — `undefined: NewMapStoreWithEnroll`, `EnrollLookup` undefined on `MapStore`/`FileStore`, and the `var _ authgate.DeviceStore` assertion fails to compile.

- [ ] **Step 3: Replace `core/authgate/registry.go` with:**

```go
package authgate

// DeviceStore resolves credentials for the in-tunnel auth gate: a device id to
// its per-device AUTH PSK (KindDevice), and a user id to its enrollment PSK
// (KindEnroll). Implementations must be safe for concurrent use by the gate.
type DeviceStore interface {
	// Lookup returns the per-device AUTH PSK for deviceID and whether it exists.
	Lookup(deviceID [16]byte) (psk []byte, ok bool)
	// EnrollLookup returns the enrollment PSK for userID and whether that user
	// exists and may enroll.
	EnrollLookup(userID [16]byte) (psk []byte, ok bool)
}

// MapStore is an in-memory DeviceStore for phase-1 and tests. It is read-only
// after construction, so it needs no locking.
type MapStore struct {
	devices map[[16]byte][]byte
	enroll  map[[16]byte][]byte
}

// NewMapStore builds a MapStore from a deviceID->PSK map (nil is allowed and
// yields an empty store) with no enrollment users. The caller must not mutate
// the map afterward.
func NewMapStore(devices map[[16]byte][]byte) *MapStore {
	return NewMapStoreWithEnroll(devices, nil)
}

// NewMapStoreWithEnroll builds a MapStore from a deviceID->PSK map and a
// userID->enrollPSK map (either may be nil). The caller must not mutate the maps
// afterward.
func NewMapStoreWithEnroll(devices, enroll map[[16]byte][]byte) *MapStore {
	if devices == nil {
		devices = map[[16]byte][]byte{}
	}
	if enroll == nil {
		enroll = map[[16]byte][]byte{}
	}
	return &MapStore{devices: devices, enroll: enroll}
}

// Lookup implements DeviceStore.
func (s *MapStore) Lookup(deviceID [16]byte) ([]byte, bool) {
	psk, ok := s.devices[deviceID]
	return psk, ok
}

// EnrollLookup implements DeviceStore.
func (s *MapStore) EnrollLookup(userID [16]byte) ([]byte, bool) {
	psk, ok := s.enroll[userID]
	return psk, ok
}
```

- [ ] **Step 4: Add `EnrollLookup` to `core/provision/store.go`**

Immediately after the existing `EnrollPSK` method (the method that ends near store.go:73), insert:
```go
// EnrollLookup implements authgate.DeviceStore for the enrollment path: it
// returns the user's decrypted enrollment PSK. It is EnrollPSK under the name
// the gate's interface expects.
func (s *FileStore) EnrollLookup(userID [16]byte) ([]byte, bool) {
	return s.EnrollPSK(userID)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test -race ./authgate/ ./provision/ -v 2>&1 | tail -30
/home/goodvin/.local/go/bin/go vet ./authgate/ ./provision/
/home/goodvin/.local/go/bin/go build ./server/
```
Expected: PASS / clean; `core/server` still builds (FileStore satisfies the extended interface).

- [ ] **Step 6: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/authgate/registry.go core/authgate/registry_test.go core/provision/store.go core/provision/store_test.go
git commit -m "feat(authgate): DeviceStore.EnrollLookup for the enroll path

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Gate branches on kind → Result{Kind, UserID}

**Files:** Modify `core/authgate/gate.go`, `core/authgate/gate_test.go`.

`Result` grows `Kind` and `UserID`. `Handle` selects the device or enroll PSK by `tok.Kind`, rejects an unknown kind to the decoy, and reports the verified id under the matching field. Replay/timestamp checks apply to both kinds (probe-resistance preserved).

- [ ] **Step 1: Write the failing tests (append to `core/authgate/gate_test.go`)**

```go
func TestGateEnrollPath(t *testing.T) {
	uid := [16]byte{4, 5, 6}
	psk := []byte("enroll-psk")
	g := NewGate(NewMapStoreWithEnroll(nil, map[[16]byte][]byte{uid: psk}), nil)
	const now = int64(1_700_000_000)
	g.now = fixedClock(now)

	client, server := net.Pipe()
	defer client.Close()
	go func() {
		tok, _ := MakeEnrollToken(psk, uid, time.Unix(now, 0))
		frame.WriteFrame(client, frame.TypeAuth, tok)
		frame.WriteFrame(client, frame.TypeData, []byte("after"))
	}()

	res, err := g.Handle(server)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !res.Authenticated || res.Kind != KindEnroll || res.UserID != uid {
		t.Fatalf("auth=%v kind=%d user=%x; want true enroll %x", res.Authenticated, res.Kind, res.UserID, uid)
	}
	if res.DeviceID != ([16]byte{}) {
		t.Fatal("DeviceID must be zero on the enroll path")
	}
	// The gate must consume only the AUTH frame; the next frame follows.
	typ, payload, err := frame.ReadFrame(res.Conn)
	if err != nil || typ != frame.TypeData || string(payload) != "after" {
		t.Fatalf("next frame = (%d,%q),%v; want (DATA,after)", typ, payload, err)
	}
	res.Conn.Close()
}

func TestGateDecoyOnUnknownEnrollUser(t *testing.T) {
	uid := [16]byte{1, 1}
	psk := []byte("enroll-psk")
	fd := &fakeDecoy{}
	g := NewGate(NewMapStore(nil), fd) // no enroll users
	const now = int64(1_700_000_000)
	g.now = fixedClock(now)
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		tok, _ := MakeEnrollToken(psk, uid, time.Unix(now, 0))
		frame.WriteFrame(client, frame.TypeAuth, tok)
		client.Close()
	}()
	res, _ := g.Handle(server)
	if res.Authenticated {
		t.Fatal("unknown enroll user authenticated; want decoy")
	}
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if !fd.called {
		t.Fatal("decoy not invoked for unknown enroll user")
	}
}

func TestGateDeviceTokenNotAcceptedAsEnrollOnlyID(t *testing.T) {
	// An id present only in the enroll map must NOT authenticate a KindDevice
	// token: the device lookup misses, so the connection goes to the decoy.
	id := [16]byte{2, 2}
	psk := []byte("psk")
	fd := &fakeDecoy{}
	g := NewGate(NewMapStoreWithEnroll(nil, map[[16]byte][]byte{id: psk}), fd)
	const now = int64(1_700_000_000)
	g.now = fixedClock(now)
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		tok, _ := MakeToken(psk, id, time.Unix(now, 0)) // DEVICE token
		frame.WriteFrame(client, frame.TypeAuth, tok)
		client.Close()
	}()
	res, _ := g.Handle(server)
	if res.Authenticated {
		t.Fatal("device token matched an enroll-only id; want decoy")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./authgate/ -run 'TestGateEnroll|TestGateDecoyOnUnknownEnroll|TestGateDeviceTokenNotAccepted' -v`
Expected: build error — `res.Kind` / `res.UserID` undefined.

- [ ] **Step 3: Update `core/authgate/gate.go`**

(3a) Replace the `Result` struct (gate.go:17-27) with:
```go
// Result is the outcome of Gate.Handle.
type Result struct {
	// Authenticated is true when the first frame was a valid, fresh AUTH token.
	Authenticated bool
	// Kind is the authenticated token kind (KindDevice or KindEnroll); valid only
	// when Authenticated.
	Kind uint8
	// DeviceID is the verified device; set only when Authenticated && Kind==KindDevice.
	DeviceID [16]byte
	// UserID is the verified enrolling user; set only when Authenticated && Kind==KindEnroll.
	UserID [16]byte
	// Conn is the connection positioned immediately after the AUTH frame, ready
	// for the next exchange (data path, or the enrollment request). Set only when
	// Authenticated; otherwise the gate has already handed the connection to the
	// decoy (or closed it) and Conn is nil.
	Conn net.Conn
}
```

(3b) Replace the lookup/verify/return tail of `Handle` — the block currently from `psk, ok := g.store.Lookup(tok.DeviceID)` through `return Result{Authenticated: true, DeviceID: tok.DeviceID, Conn: conn}, nil` (gate.go:83-95) — with:
```go
	var (
		psk []byte
		ok  bool
	)
	switch tok.Kind {
	case KindDevice:
		psk, ok = g.store.Lookup(tok.DeviceID)
	case KindEnroll:
		psk, ok = g.store.EnrollLookup(tok.DeviceID)
	default:
		return g.toDecoy(conn, rec.buf)
	}
	if !ok {
		return g.toDecoy(conn, rec.buf)
	}
	if err := tok.Verify(psk, g.now(), g.window); err != nil {
		return g.toDecoy(conn, rec.buf)
	}
	if g.replay.Seen(tok.Nonce) {
		return g.toDecoy(conn, rec.buf)
	}

	_ = conn.SetReadDeadline(time.Time{}) // hand a clean conn to the next exchange
	res := Result{Authenticated: true, Kind: tok.Kind, Conn: conn}
	if tok.Kind == KindEnroll {
		res.UserID = tok.DeviceID
	} else {
		res.DeviceID = tok.DeviceID
	}
	return res, nil
```

- [ ] **Step 4: Run the tests to verify they pass**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test -race ./authgate/ -v 2>&1 | tail -40
/home/goodvin/.local/go/bin/go vet ./authgate/
/home/goodvin/.local/go/bin/go build ./server/
```
Expected: PASS (all existing device-path tests still pass; new enroll tests pass); `core/server` still builds (it reads `res.DeviceID`/`res.Authenticated`; the new fields are additive).

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/authgate/gate.go core/authgate/gate_test.go
git commit -m "feat(authgate): gate branches on token kind (enroll path -> Result.UserID)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Enroll frame types + message codec

**Files:** Modify `core/frame/frame.go`, `core/frame/frame_test.go`. Create `core/enroll/enroll.go`, `core/enroll/enroll_test.go`.

- [ ] **Step 1: Write the failing tests**

Append to `core/frame/frame_test.go` (it already imports `bytes` and `testing`):
```go
func TestEnrollFrameTypesRoundTrip(t *testing.T) {
	for _, typ := range []Type{TypeEnrollRequest, TypeEnrollResponse} {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, typ, []byte("payload")); err != nil {
			t.Fatalf("WriteFrame(%d): %v", typ, err)
		}
		gotType, payload, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if gotType != typ || string(payload) != "payload" {
			t.Fatalf("round trip = (%d,%q), want (%d,payload)", gotType, payload, typ)
		}
	}
}
```

Create `core/enroll/enroll_test.go`:
```go
package enroll

import (
	"bytes"
	"testing"
)

func TestRequestRoundTrip(t *testing.T) {
	var in Request
	for i := range in.WGPublic {
		in.WGPublic[i] = byte(i)
	}
	out, err := ParseRequest(in.Marshal())
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if out.WGPublic != in.WGPublic {
		t.Fatalf("round trip = %x, want %x", out.WGPublic, in.WGPublic)
	}
}

func TestParseRequestWrongSize(t *testing.T) {
	if _, err := ParseRequest(make([]byte, 31)); err == nil {
		t.Fatal("ParseRequest(31) accepted")
	}
}

func TestResponseRoundTrip(t *testing.T) {
	in := Response{
		DeviceID:  [16]byte{1, 2, 3, 4},
		TunnelIP:  "10.100.0.7",
		DevicePSK: bytes.Repeat([]byte{0xAB}, 32),
	}
	raw, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out, err := ParseResponse(raw)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if out.DeviceID != in.DeviceID || out.TunnelIP != in.TunnelIP || !bytes.Equal(out.DevicePSK, in.DevicePSK) {
		t.Fatalf("round trip = %+v, want %+v", out, in)
	}
}

func TestParseResponseTruncated(t *testing.T) {
	if _, err := ParseResponse(make([]byte, 10)); err == nil {
		t.Fatal("ParseResponse(short) accepted")
	}
	// deviceID + pskLen says 32 but no psk bytes follow.
	bad := append(make([]byte, 16), 32)
	if _, err := ParseResponse(bad); err == nil {
		t.Fatal("ParseResponse(psk truncated) accepted")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./frame/ ./enroll/ -run 'TestEnrollFrameTypes|TestRequest|TestResponse|TestParse' -v 2>&1 | tail -20`
Expected: `frame` fails on `undefined: TypeEnrollRequest`; `enroll` fails to build (`no Go files` / undefined types).

- [ ] **Step 3: Add the frame types to `core/frame/frame.go`**

In the `const (...)` type block (frame.go:32-43), after `TypeControl Type = 4`, add:
```go
	// TypeEnrollRequest carries a device's enrollment request (its WG public key).
	TypeEnrollRequest Type = 5
	// TypeEnrollResponse carries the server's enrollment reply (device id, tunnel IP, device PSK).
	TypeEnrollResponse Type = 6
```

- [ ] **Step 4: Create `core/enroll/enroll.go`**

```go
// Package enroll defines the gvpn dynamic-enrollment exchange that runs over the
// framed, GOST-TLS-terminated connection immediately after the AUTH gate admits
// a KindEnroll connection and before the WireGuard data path: the device sends
// its fresh WireGuard public key (Request) and the server replies with the
// allocated device id, tunnel IP, and per-device PSK (Response). Pure Go, no cgo.
package enroll

import (
	"errors"
	"fmt"
)

// Request is the device->server enrollment message: the device's freshly
// generated WireGuard public key.
type Request struct {
	WGPublic [32]byte
}

// Marshal serializes the request as the raw 32-byte key.
func (r Request) Marshal() []byte {
	b := make([]byte, 32)
	copy(b, r.WGPublic[:])
	return b
}

// ParseRequest deserializes a Request.
func ParseRequest(b []byte) (Request, error) {
	if len(b) != 32 {
		return Request{}, fmt.Errorf("enroll: request is %d bytes, want 32", len(b))
	}
	var r Request
	copy(r.WGPublic[:], b)
	return r, nil
}

// Response is the server->device enrollment reply.
type Response struct {
	DeviceID  [16]byte
	TunnelIP  string
	DevicePSK []byte
}

// Marshal serializes the response as deviceID(16) || pskLen(1) || psk || tunnelIP.
func (r Response) Marshal() ([]byte, error) {
	if len(r.DevicePSK) > 255 {
		return nil, errors.New("enroll: device psk too long")
	}
	b := make([]byte, 0, 16+1+len(r.DevicePSK)+len(r.TunnelIP))
	b = append(b, r.DeviceID[:]...)
	b = append(b, byte(len(r.DevicePSK)))
	b = append(b, r.DevicePSK...)
	b = append(b, r.TunnelIP...)
	return b, nil
}

// ParseResponse deserializes a Response.
func ParseResponse(b []byte) (Response, error) {
	if len(b) < 17 {
		return Response{}, errors.New("enroll: response too short")
	}
	var r Response
	copy(r.DeviceID[:], b[:16])
	n := int(b[16])
	if len(b) < 17+n {
		return Response{}, errors.New("enroll: response psk truncated")
	}
	r.DevicePSK = append([]byte(nil), b[17:17+n]...)
	r.TunnelIP = string(b[17+n:])
	return r, nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test -race ./frame/ ./enroll/ -v 2>&1 | tail -30
/home/goodvin/.local/go/bin/go vet ./frame/ ./enroll/
```
Expected: PASS / clean.

- [ ] **Step 6: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/frame/frame.go core/frame/frame_test.go core/enroll/enroll.go core/enroll/enroll_test.go
git commit -m "feat(enroll): enrollment frame types + request/response codec

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Client + server enrollment helpers

**Files:** Modify `core/authgate/client.go`, `core/authgate/client_test.go`. Create `core/enroll/exchange.go`, `core/enroll/exchange_test.go`.

`authgate.WriteEnrollAuth` emits the KindEnroll AUTH frame (sibling of `WriteAuth`). The `enroll` package gains the post-gate wire helpers: `Exchange` (device side), `ReadRequest`/`WriteResponse` (server side).

- [ ] **Step 1: Write the failing tests**

Append to `core/authgate/client_test.go` (it already imports `net`, `testing`, `frame`):
```go
// TestWriteEnrollAuthAdmittedByGate confirms WriteEnrollAuth produces a KindEnroll
// AUTH frame the gate verifies against the user's enroll PSK. It uses the gate's
// real clock because WriteEnrollAuth stamps with time.Now().
func TestWriteEnrollAuthAdmittedByGate(t *testing.T) {
	uid := [16]byte{3, 1, 4}
	psk := []byte("enroll-psk")
	g := NewGate(NewMapStoreWithEnroll(nil, map[[16]byte][]byte{uid: psk}), nil)

	client, server := net.Pipe()
	defer client.Close()
	errc := make(chan error, 1)
	go func() { errc <- WriteEnrollAuth(client, psk, uid) }()

	res, err := g.Handle(server)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if werr := <-errc; werr != nil {
		t.Fatalf("WriteEnrollAuth: %v", werr)
	}
	if !res.Authenticated || res.Kind != KindEnroll || res.UserID != uid {
		t.Fatalf("auth=%v kind=%d user=%x; want enroll %x", res.Authenticated, res.Kind, res.UserID, uid)
	}
	res.Conn.Close()
}
```

Create `core/enroll/exchange_test.go`:
```go
package enroll

import (
	"bytes"
	"fmt"
	"net"
	"testing"
)

func TestExchangeRoundTrip(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	want := Response{DeviceID: [16]byte{9, 8, 7}, TunnelIP: "10.100.0.5", DevicePSK: bytes.Repeat([]byte{1}, 32)}
	var wgPub [32]byte
	for i := range wgPub {
		wgPub[i] = byte(255 - i)
	}

	errc := make(chan error, 1)
	go func() {
		req, err := ReadRequest(s)
		if err != nil {
			errc <- err
			return
		}
		if req.WGPublic != wgPub {
			errc <- fmt.Errorf("server got wg %x, want %x", req.WGPublic, wgPub)
			return
		}
		errc <- WriteResponse(s, want)
	}()

	got, err := Exchange(c, wgPub)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server: %v", err)
	}
	if got.DeviceID != want.DeviceID || got.TunnelIP != want.TunnelIP || !bytes.Equal(got.DevicePSK, want.DevicePSK) {
		t.Fatalf("Exchange = %+v, want %+v", got, want)
	}
}

func TestReadRequestRejectsWrongFrameType(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() { WriteResponse(c, Response{DeviceID: [16]byte{1}, DevicePSK: []byte("x")}) }() // wrong type for a request
	if _, err := ReadRequest(s); err == nil {
		t.Fatal("ReadRequest accepted a non-request frame")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./authgate/ ./enroll/ -run 'TestWriteEnrollAuth|TestExchange|TestReadRequest' -v 2>&1 | tail -20`
Expected: build errors — `undefined: WriteEnrollAuth`, `undefined: Exchange`/`ReadRequest`/`WriteResponse`.

- [ ] **Step 3: Add `WriteEnrollAuth` to `core/authgate/client.go`**

Append to `core/authgate/client.go` (it already imports `net`, `time`, `frame`):
```go
// WriteEnrollAuth sends a KindEnroll AUTH frame as the first frame on conn, using
// the user's enrollment PSK and 16-byte user id. A new device calls this on its
// first connect to bootstrap enrollment (design §7); steady-state connects use
// WriteAuth with the per-device PSK.
func WriteEnrollAuth(conn net.Conn, enrollPSK []byte, userID [16]byte) error {
	tok, err := MakeEnrollToken(enrollPSK, userID, time.Now())
	if err != nil {
		return err
	}
	return frame.WriteFrame(conn, frame.TypeAuth, tok)
}
```

- [ ] **Step 4: Create `core/enroll/exchange.go`**

```go
package enroll

import (
	"fmt"
	"net"

	"github.com/g00dvin/gvpn/core/frame"
)

// Exchange runs the device side of the enrollment exchange on an already-gated
// connection: it sends the WireGuard public key and returns the server's
// Response. The caller manages any read/write deadlines on conn.
func Exchange(conn net.Conn, wgPublic [32]byte) (Response, error) {
	if err := frame.WriteFrame(conn, frame.TypeEnrollRequest, Request{WGPublic: wgPublic}.Marshal()); err != nil {
		return Response{}, err
	}
	typ, payload, err := frame.ReadFrame(conn)
	if err != nil {
		return Response{}, err
	}
	if typ != frame.TypeEnrollResponse {
		return Response{}, fmt.Errorf("enroll: expected response frame, got type %d", typ)
	}
	return ParseResponse(payload)
}

// ReadRequest runs on the server: it reads the device's enrollment Request frame.
func ReadRequest(conn net.Conn) (Request, error) {
	typ, payload, err := frame.ReadFrame(conn)
	if err != nil {
		return Request{}, err
	}
	if typ != frame.TypeEnrollRequest {
		return Request{}, fmt.Errorf("enroll: expected request frame, got type %d", typ)
	}
	return ParseRequest(payload)
}

// WriteResponse runs on the server: it sends the enrollment Response frame.
func WriteResponse(conn net.Conn, resp Response) error {
	b, err := resp.Marshal()
	if err != nil {
		return err
	}
	return frame.WriteFrame(conn, frame.TypeEnrollResponse, b)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test -race ./authgate/ ./enroll/ -v 2>&1 | tail -40
/home/goodvin/.local/go/bin/go vet ./authgate/ ./enroll/
```
Expected: PASS / clean.

- [ ] **Step 6: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/authgate/client.go core/authgate/client_test.go core/enroll/exchange.go core/enroll/exchange_test.go
git commit -m "feat(enroll): client Exchange + server ReadRequest/WriteResponse + WriteEnrollAuth

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Final review + PR

**Files:** none (verification + PR only).

- [ ] **Step 1: Whole-module verification**

```bash
cd /home/goodvin/git/gvpn/core
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test -race ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go build ./...
```
Expected: all PASS / clean. (`gosttls` needs cgo; the rest is pure Go.)

- [ ] **Step 2: Confirm the new code stays cgo-free**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go list -deps ./enroll/ ./authgate/ ./frame/ | grep -iE 'gosttls|netstack|gvisor' || echo "OK: no cgo/netstack in enroll/authgate/frame graph"`
Expected: `OK`.

- [ ] **Step 3: Opus final code + security review** (controller dispatches a fresh Opus subagent)

Review focus: the MAC binds the kind byte (a flipped kind fails verification); enroll and device PSKs cannot cross-authenticate (an id present only in one map fails the other path); unknown kind → decoy; enroll tokens still go through timestamp window + replay-cache checks (probe-resistance preserved); `Result.UserID`/`DeviceID` are mutually exclusive by kind; the enroll Response parser validates lengths (no slice OOB on truncated/oversized psk) and never logs secrets; `Exchange`/`ReadRequest` reject the wrong frame type; the AUTH token format bump is internally consistent (Marshal/ParseToken offsets, TokenSize); `core/server` still builds & passes unchanged; `enroll`/`authgate`/`frame` stay cgo-free.

- [ ] **Step 4: Push and open PR** (trivial / `gh` — Haiku)

```bash
cd /home/goodvin/git/gvpn
git push -u origin feat/enrollment-protocol
gh pr create --base main --head feat/enrollment-protocol \
  --title "Enrollment protocol primitives: AUTH token kind, gate enroll path, ENROLL exchange" \
  --body "Adds the wire-level primitives for dynamic device enrollment (design doc §6–§7), without wiring them into the server data path (that is the next plan).

- AUTH token gains a 1-byte kind discriminator (DEVICE vs ENROLL) bound by the HMAC; TokenSize 73->74. MakeEnrollToken emits the enroll variant.
- DeviceStore.EnrollLookup(userID) added; MapStore (+NewMapStoreWithEnroll) and provision.FileStore implement it.
- Gate.Handle branches on kind: device -> Result{Kind,DeviceID}; enroll -> Result{Kind,UserID}; unknown kind or failed lookup/verify/replay -> decoy.
- New core/enroll package: Request{WGPublic} / Response{DeviceID,TunnelIP,DevicePSK} over new frame types TypeEnrollRequest/TypeEnrollResponse, with client Exchange and server ReadRequest/WriteResponse helpers. authgate.WriteEnrollAuth emits the KindEnroll AUTH frame.

Breaking: AUTH token wire format changed (kind byte); client+server ship together, no migration. Out of scope (next plan): the multiplexed server + enrollment handler that consumes these primitives (provision.AddDevice + AddPeer live), guardrail enforcement, and the gvpn-server binary.

Pure Go / cgo-free; whole module green under -race + cgo.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

---

## Self-Review

**Spec coverage (design §6–§7):** token kind byte (Task 1), user-PSK lookup (Task 2), gate enroll branch with `Result.Kind`/`UserID` (Task 3), the ENROLL request/response messages + frame types (Task 4), and client/server exchange helpers + the enroll AUTH emitter (Task 5). The server-side enrollment *handler* (allocate IP + DeviceID, mint device PSK, `AddDevice`+`AddPeer`, reply) is explicitly deferred to Plan 11, which consumes exactly these primitives (`Gate` Result.Kind/UserID, `FileStore.EnrollLookup`, `enroll.ReadRequest`/`WriteResponse`). Decoy/probe-resistance is preserved on every enroll failure path (Task 3).

**Placeholder scan:** none — every step has full code or an exact edit location (`gate.go:17-27`, `gate.go:83-95`, after `EnrollPSK` in store.go, in the frame `const` block, append to client.go/client_test.go/token_test.go/registry_test.go/frame_test.go). The only narrative edits (vs whole-file rewrites) are the two gate.go blocks and the small appends; each shows the complete replacement/added code.

**Type consistency:** `MakeToken(psk, [16]byte, time.Time) ([]byte,error)` (unchanged), `MakeEnrollToken(psk, [16]byte, time.Time) ([]byte,error)`, `Token{Version,Kind,DeviceID,Nonce,Timestamp,MAC}`, `KindDevice/KindEnroll uint8`, `TokenSize = 74`; `DeviceStore.Lookup`/`EnrollLookup(userID [16]byte) ([]byte,bool)`, `NewMapStore`/`NewMapStoreWithEnroll`, `FileStore.EnrollLookup` (delegates to `EnrollPSK`); `Result{Authenticated,Kind,DeviceID,UserID,Conn}`; `frame.TypeEnrollRequest=5`/`TypeEnrollResponse=6`; `enroll.Request{WGPublic [32]byte}` with `Marshal()/ParseRequest`, `enroll.Response{DeviceID [16]byte,TunnelIP string,DevicePSK []byte}` with `Marshal() ([]byte,error)`/`ParseResponse`; `enroll.Exchange(net.Conn,[32]byte) (Response,error)`, `enroll.ReadRequest(net.Conn) (Request,error)`, `enroll.WriteResponse(net.Conn,Response) error`; `authgate.WriteEnrollAuth(net.Conn,[]byte,[16]byte) error`. `provision.FileStore` continues to satisfy `authgate.DeviceStore` (now with two methods), asserted in store_test.go.
