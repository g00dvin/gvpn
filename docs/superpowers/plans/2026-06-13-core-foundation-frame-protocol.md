# Core Foundation — Monorepo Scaffold + Frame Protocol Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bootstrap the `g00dvin/gvpn` monorepo on GitHub and implement the typed frame protocol + `PacketTransport` interface that the whole transport stack depends on.

**Architecture:** Pure-Go `core/` module, no native dependencies yet. The frame protocol (resolving spec-review findings C3/L1) is a versioned, typed length-prefixed codec over any `io.Reader`/`io.Writer`. `PacketTransport` (spec §5) is the interface WireGuard couples to; a `StreamTransport` adapts a framed byte stream into it. This is Plan 1 of a multi-plan effort.

**Tech Stack:** Go 1.24, stdlib only (`encoding/binary`, `io`, `net`, `sync`, `testing`). GitHub Actions for CI (already defined in `.github/workflows/build.yml`).

**Design reference:** `docs/superpowers/specs/2026-06-13-gvpn-transport-design.md` (§4 frame protocol, §5 transport).

---

## Plan roadmap (context — do not implement beyond Plan 1 here)

1. **Plan 1 (this doc):** Monorepo scaffold + frame protocol + `PacketTransport`.
2. Plan 2: Reconnecting TCP transport adapter (framing + `SESSION_BIND`, no TLS yet).
3. Plan 3: GOST TLS `net.Conn` via CGO (OpenSSL 3.x + GOST provider).
4. Plan 4: In-tunnel auth gate + decoy reverse-proxy (server camouflage).
5. Plan 5: `wireguard-go` integration through `PacketTransport`.
6. Plan 6: Server assembly + YAML config + `gvpn-provision` CLI.
7. Plan 7+: Windows (Wails), Android (gomobile), iOS (gomobile + NE memory spike).

---

## File structure (Plan 1)

```
.gitignore                              repo ignore rules
go.work                                 Go workspace (use ./core)
core/go.mod                             module github.com/g00dvin/gvpn/core
core/frame/frame.go                     frame types, constants, header marshal/parse
core/frame/writer.go                    WriteFrame
core/frame/reader.go                    ReadFrame
core/frame/frame_test.go                header + write + read tests
core/transport/transport.go            PacketTransport interface + StreamTransport
core/transport/transport_test.go       StreamTransport round-trip tests
.github/workflows/build.yml             MODIFY: drop cache-dependency-path (no go.sum yet)
```

---

## Task 1: Bootstrap the monorepo and push to GitHub

**Files:**
- Create: `.gitignore`, `go.work`, `core/go.mod`
- Modify: `.github/workflows/build.yml` (remove two `cache-dependency-path` lines)

- [ ] **Step 1: Initialize git on the `main` branch**

Run:
```bash
cd /home/goodvin/git/gvpn
git init -b main
git remote add origin git@github.com:g00dvin/gvpn.git
```
Expected: `Initialized empty Git repository`; remote added with no output.

- [ ] **Step 2: Create `.gitignore`**

Create `.gitignore`:
```gitignore
# Go build output
/dist/
bin/
*.exe
*.test
*.out

# Mobile / desktop build artifacts
*.aar
*.xcframework/
client/windows/build/bin/
client/android/app/build/
client/android/app/libs/

# Native libraries
*.so
*.dylib

# Secrets & certificates — never commit
*.key
*.crt
*.pem
server.yaml

# OS / editor
.DS_Store
.idea/
.vscode/
```

- [ ] **Step 3: Create the Go workspace and core module**

Create `go.work`:
```
go 1.24

use ./core
```

Create `core/go.mod`:
```
module github.com/g00dvin/gvpn/core

go 1.24
```

- [ ] **Step 4: Fix the CI workflow (no `go.sum` exists yet)**

The frame protocol has zero external dependencies, so no `go.sum` is produced. `actions/setup-go` with an explicit `cache-dependency-path` pointing at a missing file fails the job. Remove both occurrences.

In `.github/workflows/build.yml`, delete the line `          cache-dependency-path: core/go.sum` (in the `core` job) and the line `          cache-dependency-path: server/go.sum` (in the `server` job). Leave the rest of each `setup-go` step intact.

- [ ] **Step 5: Verify the module builds locally**

Run:
```bash
cd /home/goodvin/git/gvpn/core && go build ./... && go vet ./...
```
Expected: no output, exit code 0 (empty module builds clean).

- [ ] **Step 6: Initial commit and push**

Run:
```bash
cd /home/goodvin/git/gvpn
git add .gitignore go.work core/go.mod .github/ docs/ spec.md spec-review.md CLAUDE.md
git commit -m "chore: bootstrap gvpn monorepo (workspace, core module, CI)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push -u origin main
```
Expected: push succeeds; `origin/main` now tracks `main`.

- [ ] **Step 7: Confirm CI was triggered**

Run:
```bash
gh run list --limit 3
```
Expected: a `build` workflow run appears for the push (queued/in_progress/completed). The `core` job runs `go vet`/`go test` (passes — no tests yet); `server`/`windows`/`android`/`ios` jobs skip with a notice.

- [ ] **Step 8: Create the feature branch for the rest of the plan**

Run:
```bash
cd /home/goodvin/git/gvpn
git checkout -b feat/core-foundation
```
Expected: `Switched to a new branch 'feat/core-foundation'`.

---

## Task 2: Frame types, constants, and header marshal/parse

**Files:**
- Create: `core/frame/frame.go`
- Test: `core/frame/frame_test.go`

- [ ] **Step 1: Write the failing test**

Create `core/frame/frame_test.go`:
```go
package frame

import (
	"bytes"
	"testing"
)

func TestHeaderMarshalParseRoundTrip(t *testing.T) {
	h := Header{Version: Version1, Type: TypeData, Length: 0x1234}
	b := h.Marshal()
	if len(b) != HeaderSize {
		t.Fatalf("marshal length = %d, want %d", len(b), HeaderSize)
	}
	want := []byte{0x01, 0x00, 0x12, 0x34}
	if !bytes.Equal(b, want) {
		t.Fatalf("marshal = % x, want % x", b, want)
	}
	got, err := ParseHeader(b)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if got != h {
		t.Fatalf("parsed = %+v, want %+v", got, h)
	}
}

func TestParseHeaderShort(t *testing.T) {
	_, err := ParseHeader([]byte{0x01, 0x00})
	if err != ErrShortHeader {
		t.Fatalf("err = %v, want ErrShortHeader", err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd core && go test ./frame/ -run TestHeader -v`
Expected: FAIL — `undefined: Header`, `undefined: Version1`, etc.

- [ ] **Step 3: Write the implementation**

Create `core/frame/frame.go`:
```go
// Package frame implements the gvpn transport frame protocol: a versioned,
// typed, length-prefixed codec carrying one payload (e.g. a WireGuard packet)
// per frame over any byte stream.
//
// Wire format (network byte order):
//
//	uint8  version   protocol version (starts at 1)
//	uint8  type      frame Type
//	uint16 length    payload length, 0..MaxPayloadSize
//	[length]byte     payload
package frame

import (
	"encoding/binary"
	"errors"
)

// Version1 is the initial protocol version.
const Version1 uint8 = 1

// HeaderSize is the fixed size of a frame header in bytes.
const HeaderSize = 4

// MaxPayloadSize is the largest payload a single frame may carry. It equals the
// maximum value of the uint16 length field, so the field type is itself the
// overflow guard: a frame can never request more than 64 KiB of allocation.
const MaxPayloadSize = 65535

// Type identifies what a frame carries.
type Type uint8

const (
	// TypeData carries a WireGuard packet.
	TypeData Type = 0
	// TypeAuth carries the in-tunnel authentication token (first frame).
	TypeAuth Type = 1
	// TypeHeartbeat is a transport-layer keepalive.
	TypeHeartbeat Type = 2
	// TypeSessionBind carries a reconnect/resume token.
	TypeSessionBind Type = 3
	// TypeControl is reserved for future orchestrator control messages.
	TypeControl Type = 4
)

// Header is the fixed-size frame header.
type Header struct {
	Version uint8
	Type    Type
	Length  uint16
}

// Errors returned by the frame codec.
var (
	ErrShortHeader        = errors.New("frame: header too short")
	ErrPayloadTooLarge    = errors.New("frame: payload exceeds max size")
	ErrUnsupportedVersion = errors.New("frame: unsupported version")
)

// Marshal serializes the header into a HeaderSize-byte slice.
func (h Header) Marshal() []byte {
	b := make([]byte, HeaderSize)
	b[0] = h.Version
	b[1] = byte(h.Type)
	binary.BigEndian.PutUint16(b[2:4], h.Length)
	return b
}

// ParseHeader deserializes a header from b, which must be at least HeaderSize.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, ErrShortHeader
	}
	return Header{
		Version: b[0],
		Type:    Type(b[1]),
		Length:  binary.BigEndian.Uint16(b[2:4]),
	}, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd core && go test ./frame/ -run TestHeader -v`
Expected: PASS for `TestHeaderMarshalParseRoundTrip` and `TestParseHeaderShort`.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/frame/frame.go core/frame/frame_test.go
git commit -m "feat(frame): typed versioned frame header

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: WriteFrame

**Files:**
- Create: `core/frame/writer.go`
- Test: `core/frame/frame_test.go` (append)

- [ ] **Step 1: Write the failing test**

Append to `core/frame/frame_test.go`:
```go
func TestWriteFrame(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, TypeData, []byte("hi")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	want := []byte{0x01, 0x00, 0x00, 0x02, 'h', 'i'}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("frame = % x, want % x", buf.Bytes(), want)
	}
}

func TestWriteFrameTooLarge(t *testing.T) {
	var buf bytes.Buffer
	err := WriteFrame(&buf, TypeData, make([]byte, MaxPayloadSize+1))
	if err != ErrPayloadTooLarge {
		t.Fatalf("err = %v, want ErrPayloadTooLarge", err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd core && go test ./frame/ -run TestWriteFrame -v`
Expected: FAIL — `undefined: WriteFrame`.

- [ ] **Step 3: Write the implementation**

Create `core/frame/writer.go`:
```go
package frame

import "io"

// WriteFrame writes a single frame (header + payload) to w. It returns
// ErrPayloadTooLarge if payload exceeds MaxPayloadSize. The header and payload
// are written in one Write call so concurrent writers (holding an external
// lock) never interleave a header with another frame's payload.
func WriteFrame(w io.Writer, t Type, payload []byte) error {
	if len(payload) > MaxPayloadSize {
		return ErrPayloadTooLarge
	}
	h := Header{Version: Version1, Type: t, Length: uint16(len(payload))}
	buf := make([]byte, 0, HeaderSize+len(payload))
	buf = append(buf, h.Marshal()...)
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd core && go test ./frame/ -run TestWriteFrame -v`
Expected: PASS for both write tests.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/frame/writer.go core/frame/frame_test.go
git commit -m "feat(frame): WriteFrame with size guard

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: ReadFrame

**Files:**
- Create: `core/frame/reader.go`
- Test: `core/frame/frame_test.go` (append)

- [ ] **Step 1: Write the failing test**

Append to `core/frame/frame_test.go`:
```go
import_marker_for_reader_test := 0
_ = import_marker_for_reader_test
```
Note: do NOT add the snippet above — it is a reminder that `io` is needed. Instead append the following real tests, and ensure the test file's import block includes `"io"` and `"strings"` (update the existing `import (...)` at the top of `core/frame/frame_test.go` to:
```go
import (
	"bytes"
	"io"
	"strings"
	"testing"
)
```
). Then append:
```go
func TestReadFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, TypeHeartbeat, []byte("ping")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	typ, payload, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if typ != TypeHeartbeat {
		t.Fatalf("type = %d, want %d", typ, TypeHeartbeat)
	}
	if string(payload) != "ping" {
		t.Fatalf("payload = %q, want %q", payload, "ping")
	}
}

func TestReadFrameUnsupportedVersion(t *testing.T) {
	r := bytes.NewReader([]byte{0x09, 0x00, 0x00, 0x00})
	_, _, err := ReadFrame(r)
	if err != ErrUnsupportedVersion {
		t.Fatalf("err = %v, want ErrUnsupportedVersion", err)
	}
}

func TestReadFrameTruncatedPayload(t *testing.T) {
	// Header claims 4 bytes of payload but only 2 are present.
	r := strings.NewReader("\x01\x00\x00\x04hi")
	_, _, err := ReadFrame(r)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd core && go test ./frame/ -run TestReadFrame -v`
Expected: FAIL — `undefined: ReadFrame`.

- [ ] **Step 3: Write the implementation**

Create `core/frame/reader.go`:
```go
package frame

import "io"

// ReadFrame reads one frame from r and returns its type and payload. It uses
// io.ReadFull, so a truncated stream yields io.ErrUnexpectedEOF and a clean EOF
// before any byte yields io.EOF. The payload length is bounded by the uint16
// header field (<= MaxPayloadSize), so allocation is always safe.
func ReadFrame(r io.Reader) (Type, []byte, error) {
	hb := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, hb); err != nil {
		return 0, nil, err
	}
	h, err := ParseHeader(hb)
	if err != nil {
		return 0, nil, err
	}
	if h.Version != Version1 {
		return 0, nil, ErrUnsupportedVersion
	}
	payload := make([]byte, h.Length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return h.Type, payload, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd core && go test ./frame/ -v`
Expected: PASS for all frame tests (header, write, read).

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/frame/reader.go core/frame/frame_test.go
git commit -m "feat(frame): ReadFrame with version + truncation handling

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: PacketTransport interface + StreamTransport

**Files:**
- Create: `core/transport/transport.go`
- Test: `core/transport/transport_test.go`

- [ ] **Step 1: Write the failing test**

Create `core/transport/transport_test.go`:
```go
package transport

import (
	"net"
	"testing"
)

// compile-time assertion that StreamTransport implements PacketTransport.
var _ PacketTransport = (*StreamTransport)(nil)

func TestStreamTransportRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	a := NewStreamTransport(c1)
	b := NewStreamTransport(c2)

	go func() {
		if err := a.WritePacket([]byte("hello")); err != nil {
			t.Errorf("WritePacket: %v", err)
		}
	}()

	got, err := b.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("packet = %q, want %q", got, "hello")
	}
}

func TestStreamTransportCloseUnblocksRead(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	a := NewStreamTransport(c1)

	errc := make(chan error, 1)
	go func() {
		_, err := a.ReadPacket()
		errc <- err
	}()

	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-errc; err == nil {
		t.Fatal("ReadPacket returned nil error after Close, want non-nil")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd core && go test ./transport/ -v`
Expected: FAIL — `undefined: PacketTransport`, `undefined: StreamTransport`.

- [ ] **Step 3: Write the implementation**

Create `core/transport/transport.go`:
```go
// Package transport defines the boundary between the VPN engine and the
// underlying byte stream. WireGuard interacts with the network exclusively
// through PacketTransport (spec §5).
package transport

import (
	"io"
	"sync"

	"github.com/g00dvin/gvpn/core/frame"
)

// PacketTransport is the only interface the WireGuard engine uses to move
// packets. Implementations hide framing, TLS, and (later) reconnection.
type PacketTransport interface {
	// ReadPacket returns the next VPN packet, blocking until one is available.
	ReadPacket() ([]byte, error)
	// WritePacket sends one VPN packet.
	WritePacket([]byte) error
	// Close releases the transport. Pending Read/Write calls return an error.
	Close() error
}

// StreamTransport adapts a framed byte stream (any io.ReadWriteCloser) into a
// PacketTransport. Each VPN packet is carried in a single DATA frame. Non-DATA
// frames are skipped here; higher layers handle them in later plans.
type StreamTransport struct {
	conn io.ReadWriteCloser
	rmu  sync.Mutex
	wmu  sync.Mutex
}

// NewStreamTransport wraps conn.
func NewStreamTransport(conn io.ReadWriteCloser) *StreamTransport {
	return &StreamTransport{conn: conn}
}

// ReadPacket reads frames until a DATA frame arrives and returns its payload.
func (t *StreamTransport) ReadPacket() ([]byte, error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()
	for {
		typ, payload, err := frame.ReadFrame(t.conn)
		if err != nil {
			return nil, err
		}
		if typ == frame.TypeData {
			return payload, nil
		}
	}
}

// WritePacket writes p as a single DATA frame.
func (t *StreamTransport) WritePacket(p []byte) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	return frame.WriteFrame(t.conn, frame.TypeData, p)
}

// Close closes the underlying connection.
func (t *StreamTransport) Close() error {
	return t.conn.Close()
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd core && go test ./transport/ -v`
Expected: PASS for `TestStreamTransportRoundTrip` and `TestStreamTransportCloseUnblocksRead`.

- [ ] **Step 5: Run the full module test suite + vet**

Run: `cd core && go test ./... && go vet ./...`
Expected: all packages PASS, vet clean.

- [ ] **Step 6: Commit, push, and open a PR**

```bash
cd /home/goodvin/git/gvpn
git add core/transport/transport.go core/transport/transport_test.go
git commit -m "feat(transport): PacketTransport interface + StreamTransport

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push -u origin feat/core-foundation
gh pr create --title "Core foundation: frame protocol + PacketTransport" \
  --body "Implements Plan 1: monorepo scaffold, typed frame protocol (resolves spec-review C3/L1), and the PacketTransport boundary (spec §5). Pure Go, no native deps.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```
Expected: branch pushed; PR created; CI `build` runs with the `core` job green and the others skipped.

---

## Self-Review

**Spec coverage (Plan 1 scope):**
- Frame protocol typed header (design §4, finding C3/L1) → Tasks 2–4. ✓
- `PacketTransport` interface (spec §5) → Task 5. ✓
- Monorepo + GitHub + CI (spec §20) → Task 1. ✓
- Out of Plan 1 scope (later plans): GOST TLS, reconnection, auth/decoy, wireguard-go, clients. Tracked in roadmap. ✓

**Placeholder scan:** No TBD/TODO in implementation steps. The only prose-without-code step is Task 1 Step 4 (a precise two-line deletion in an existing file) and Task 4 Step 1 (explicit instruction to update the test import block) — both name exact lines. The "import_marker" snippet in Task 4 Step 1 is explicitly labeled "do NOT add" and exists only to flag the import-block edit. ✓

**Type consistency:** `Header{Version,Type,Length}`, `Version1`, `HeaderSize`, `MaxPayloadSize`, `Type` constants (`TypeData=0 … TypeControl=4`), `WriteFrame(io.Writer, Type, []byte) error`, `ReadFrame(io.Reader) (Type, []byte, error)`, errors `ErrShortHeader/ErrPayloadTooLarge/ErrUnsupportedVersion`, `PacketTransport`, `StreamTransport`, `NewStreamTransport` — names and signatures match across Tasks 2–5. Module path `github.com/g00dvin/gvpn/core` consistent in `core/go.mod` and the transport import. ✓
