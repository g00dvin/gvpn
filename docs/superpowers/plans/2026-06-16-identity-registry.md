# Identity & Registry Rework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.
>
> **Per-task model assignment (standing rule):** **Sonnet** subagent implements each code task; **Opus** (controller) manages tasks and reviews each diff, and dispatches a fresh **Opus** subagent for the final review; **Haiku** subagent does the `gh` push + PR.

**Goal:** Rework the gvpn provisioning layer into a user→device identity model with secrets encrypted at rest, IP allocation, a read-write registry, and a `gvpn-provision` CLI with user/device subcommands that emit an enrollment bundle as file / deep-link / QR.

**Architecture:** A new registry model — a `Registry{Users, Devices}` JSON object — replaces the old flat `[]Device` array. Per-device AUTH PSKs and per-user enrollment PSKs are stored AEAD-encrypted (XChaCha20-Poly1305) under a master key supplied via `GVPN_MASTER_KEY` / key-file, never in config. `FileStore` becomes a read-write, mutex-guarded, atomically-persisted store that decrypts PSKs in memory (so `authgate.DeviceStore` is unchanged). Tunnel IPs are allocated from a subnet at provision time. The CLI gains `user`/`device` subcommands. `core/server` keeps compiling/passing throughout (its `server.go` only uses `WGPublicKey`, which is retained; only its tests are updated).

**Tech Stack:** Go 1.24, stdlib + `golang.org/x/crypto/chacha20poly1305`, `github.com/skip2/go-qrcode` (pure Go QR). Toolchain `/home/goodvin/.local/go/bin/go`. Module `github.com/g00dvin/gvpn/core`. No cgo in `core/provision`.

**Design reference:** `docs/superpowers/specs/2026-06-16-user-identity-enrollment-admin-design.md` §4 (identity), §5 (secrets at rest), §7 (IPAM), §8 (bundle), §15 (Plan 9 scope).

---

## Conventions

- Toolchain: `/home/goodvin/.local/go/bin/go`. Run tests with `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./provision/ ./cmd/...`.
- Branch `feat/identity-registry` off `main` (already created; the design spec is committed there).
- Commits end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Pre-existing untracked files (`core/gvpn-provision` binary, `go.work.sum`) must NOT be committed — only `git add` the files each task names.
- **Breaking change, no migration:** the registry format changes (object, renamed/encrypted fields). Existing dev registries are regenerated. Do not write migration code.

## Decisions locked for this plan

- **AEAD:** XChaCha20-Poly1305 (`x/crypto/chacha20poly1305`, `NewX`), 24-byte random nonce, stored `base64(nonce‖ciphertext)`.
- **Master key:** 32 bytes; from `GVPN_MASTER_KEY` (64 hex chars) or a key file (64 hex chars, trimmed).
- **User id:** each user gets a stored 16-byte UUIDv4 (`User.ID`, canonical hex) that backs `kind=ENROLL` tokens later (Plan 10).
- **QR library:** `github.com/skip2/go-qrcode` (pure Go; PNG + `ToSmallString` terminal).
- **Default subnet:** `10.100.0.0/24`, reserve the network address and `.1` (server TUN); allocate from `.2`.

## File structure

```
core/provision/cipher.go        Cipher (XChaCha20-Poly1305), LoadMasterKey, Seal/Open
core/provision/cipher_test.go
core/provision/ipam.go          AllocateIP(used, subnet)
core/provision/ipam_test.go
core/provision/registry.go      Registry{Users,Devices}, User, Device, LoadRegistry/SaveRegistry  (REWRITE)
core/provision/registry_test.go (REWRITE)
core/provision/store.go         FileStore: read-write, mutex-guarded, persisted (MOVED out of registry.go)
core/provision/store_test.go
core/provision/provision.go     Generate/Material/NewUser rework; Bundle gains TunnelIP             (REWRITE)
core/provision/provision_test.go(REWRITE)
core/provision/bundle.go        EnrollURI encode/parse
core/provision/bundle_test.go
core/provision/emit.go          WriteQRPNG, TerminalQR (skip2/go-qrcode)
core/provision/emit_test.go
core/cmd/gvpn-provision/main.go user/device subcommands, master key, emission                       (REWRITE)
core/cmd/gvpn-provision/main_test.go (REWRITE)
core/server/server_test.go      update to new provision API (keep main green)
core/server/e2e_test.go         update to new provision API (keep main green)
```

---

## Task 1: AEAD cipher + master key

**Files:** Create `core/provision/cipher.go`, `core/provision/cipher_test.go`.

- [ ] **Step 1: Write the failing test**

Create `core/provision/cipher_test.go`:
```go
package provision

import (
	"os"
	"strings"
	"testing"
)

func testKeyHex() string { return strings.Repeat("ab", 32) } // 32 bytes

func TestCipherSealOpenRoundTrip(t *testing.T) {
	c, err := NewCipherFromHex(testKeyHex())
	if err != nil {
		t.Fatalf("NewCipherFromHex: %v", err)
	}
	plain := []byte("super-secret-psk")
	enc, err := c.Seal(plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if strings.Contains(enc, "super-secret") {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := c.Open(enc)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("round trip = %q, want %q", got, plain)
	}
}

func TestCipherSealIsNondeterministic(t *testing.T) {
	c, _ := NewCipherFromHex(testKeyHex())
	a, _ := c.Seal([]byte("x"))
	b, _ := c.Seal([]byte("x"))
	if a == b {
		t.Fatal("Seal must use a fresh nonce each call")
	}
}

func TestCipherOpenRejectsTamper(t *testing.T) {
	c, _ := NewCipherFromHex(testKeyHex())
	enc, _ := c.Seal([]byte("hello"))
	if _, err := c.Open(enc + "AA"); err == nil {
		t.Fatal("Open accepted tampered ciphertext")
	}
}

func TestLoadMasterKeyFromEnv(t *testing.T) {
	t.Setenv("GVPN_MASTER_KEY", testKeyHex())
	key, err := LoadMasterKey("")
	if err != nil {
		t.Fatalf("LoadMasterKey env: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key len = %d, want 32", len(key))
	}
}

func TestLoadMasterKeyFromFile(t *testing.T) {
	t.Setenv("GVPN_MASTER_KEY", "")
	p := t.TempDir() + "/master.key"
	if err := os.WriteFile(p, []byte(testKeyHex()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := LoadMasterKey(p)
	if err != nil {
		t.Fatalf("LoadMasterKey file: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key len = %d, want 32", len(key))
	}
}

func TestLoadMasterKeyMissing(t *testing.T) {
	t.Setenv("GVPN_MASTER_KEY", "")
	if _, err := LoadMasterKey(""); err == nil {
		t.Fatal("expected error when no key source is given")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./provision/ -run TestCipher -v`
Expected: FAIL — `undefined: NewCipherFromHex` (and `LoadMasterKey`).

- [ ] **Step 3: Write the implementation**

Create `core/provision/cipher.go`:
```go
package provision

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher encrypts at-rest secrets (device/enroll PSKs) with XChaCha20-Poly1305
// under a 32-byte master key. Stored form is base64(nonce || ciphertext).
type Cipher struct{ aead interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
} }

// NewCipher builds a Cipher from a 32-byte key.
func NewCipher(key []byte) (*Cipher, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("provision: cipher: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// NewCipherFromHex builds a Cipher from a 64-char hex key.
func NewCipherFromHex(h string) (*Cipher, error) {
	key, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil {
		return nil, fmt.Errorf("provision: master key hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("provision: master key is %d bytes, want 32", len(key))
	}
	return NewCipher(key)
}

// Seal encrypts plain and returns base64(nonce || ciphertext).
func (c *Cipher) Seal(plain []byte) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := c.aead.Seal(nonce, nonce, plain, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Open reverses Seal.
func (c *Cipher) Open(enc string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("provision: cipher base64: %w", err)
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("provision: ciphertext too short")
	}
	return c.aead.Open(nil, raw[:ns], raw[ns:], nil)
}

// LoadMasterKey returns the 32-byte master key from GVPN_MASTER_KEY (64 hex
// chars) or, if that is empty, from the file at keyFile (64 hex chars).
func LoadMasterKey(keyFile string) ([]byte, error) {
	if env := strings.TrimSpace(os.Getenv("GVPN_MASTER_KEY")); env != "" {
		return decodeKey(env)
	}
	if keyFile != "" {
		raw, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("provision: read master key file: %w", err)
		}
		return decodeKey(string(raw))
	}
	return nil, errors.New("provision: no master key (set GVPN_MASTER_KEY or pass a key file)")
}

func decodeKey(h string) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil {
		return nil, fmt.Errorf("provision: master key hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("provision: master key is %d bytes, want 32", len(key))
	}
	return key, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./provision/ -run 'TestCipher|TestLoadMasterKey' -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./provision/`.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/provision/cipher.go core/provision/cipher_test.go
git commit -m "feat(provision): AEAD cipher + master-key loading

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: IP allocation (IPAM)

**Files:** Create `core/provision/ipam.go`, `core/provision/ipam_test.go`.

- [ ] **Step 1: Write the failing test**

Create `core/provision/ipam_test.go`:
```go
package provision

import (
	"net/netip"
	"testing"
)

func TestAllocateIPFirstIsDotTwo(t *testing.T) {
	subnet := netip.MustParsePrefix("10.100.0.0/24")
	got, err := AllocateIP(nil, subnet)
	if err != nil {
		t.Fatalf("AllocateIP: %v", err)
	}
	if got != netip.MustParseAddr("10.100.0.2") {
		t.Fatalf("first alloc = %v, want 10.100.0.2 (.0 network, .1 server reserved)", got)
	}
}

func TestAllocateIPSkipsUsed(t *testing.T) {
	subnet := netip.MustParsePrefix("10.100.0.0/24")
	used := []netip.Addr{
		netip.MustParseAddr("10.100.0.2"),
		netip.MustParseAddr("10.100.0.3"),
	}
	got, err := AllocateIP(used, subnet)
	if err != nil {
		t.Fatalf("AllocateIP: %v", err)
	}
	if got != netip.MustParseAddr("10.100.0.4") {
		t.Fatalf("alloc = %v, want 10.100.0.4", got)
	}
}

func TestAllocateIPExhausted(t *testing.T) {
	subnet := netip.MustParsePrefix("10.100.0.0/30") // hosts: .1 (reserved), .2 usable, .3 broadcast
	used := []netip.Addr{netip.MustParseAddr("10.100.0.2")}
	if _, err := AllocateIP(used, subnet); err == nil {
		t.Fatal("expected exhaustion error")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./provision/ -run TestAllocateIP -v`
Expected: FAIL — `undefined: AllocateIP`.

- [ ] **Step 3: Write the implementation**

Create `core/provision/ipam.go`:
```go
package provision

import (
	"errors"
	"net/netip"
)

// AllocateIP returns the lowest free host in subnet that is not in used. It
// reserves the network address and the first host (.1, the server TUN), and for
// IPv4 it skips the broadcast address. Allocation starts at the second host.
func AllocateIP(used []netip.Addr, subnet netip.Prefix) (netip.Addr, error) {
	subnet = subnet.Masked()
	taken := make(map[netip.Addr]bool, len(used))
	for _, a := range used {
		taken[a] = true
	}
	bcast := broadcast(subnet)
	// First host = network+1 (reserved for the server); start candidates at +2.
	addr := subnet.Addr().Next() // .1 (reserved)
	addr = addr.Next()           // .2 (first allocatable)
	for subnet.Contains(addr) {
		if subnet.Addr().Is4() && addr == bcast {
			break
		}
		if !taken[addr] {
			return addr, nil
		}
		addr = addr.Next()
	}
	return netip.Addr{}, errors.New("provision: subnet exhausted")
}

// broadcast returns the all-ones host address of an IPv4 prefix (zero value for IPv6).
func broadcast(p netip.Prefix) netip.Addr {
	if !p.Addr().Is4() {
		return netip.Addr{}
	}
	b := p.Addr().As4()
	host := 32 - p.Bits()
	for i := 0; i < host; i++ {
		byteIdx := 3 - i/8
		b[byteIdx] |= 1 << (uint(i) % 8)
	}
	return netip.AddrFrom4(b)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./provision/ -run TestAllocateIP -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./provision/`.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/provision/ipam.go core/provision/ipam_test.go
git commit -m "feat(provision): tunnel-IP allocation (AllocateIP)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Registry model + load/save

**Files:** Rewrite `core/provision/registry.go` and `core/provision/registry_test.go`. (The `FileStore` type currently in `registry.go` moves to `store.go` in Task 4 — for this task, delete it from `registry.go`; the package will not build until Task 4 restores a `FileStore`. Run only the registry tests in Step 4 with `-run`.)

- [ ] **Step 1: Write the failing test**

Replace `core/provision/registry_test.go` with:
```go
package provision

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRegistrySaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	reg := Registry{
		Users: []User{{
			Handle: "alice", ID: "11111111-1111-4111-8111-111111111111",
			EnrollPSKEnc: "enc", DeviceCap: 5, EnrollOpen: true, CreatedAt: time.Unix(1, 0).UTC(),
		}},
		Devices: []Device{{
			DeviceID: "22222222-2222-4222-8222-222222222222", User: "alice",
			WGPublic: "aa", TunnelIP: "10.100.0.2", AuthPSKEnc: "enc2",
			CreatedAt: time.Unix(2, 0).UTC(), Source: "admin",
		}},
	}
	if err := SaveRegistry(path, reg); err != nil {
		t.Fatalf("SaveRegistry: %v", err)
	}
	got, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if len(got.Users) != 1 || got.Users[0].Handle != "alice" {
		t.Fatalf("users = %+v", got.Users)
	}
	if len(got.Devices) != 1 || got.Devices[0].TunnelIP != "10.100.0.2" {
		t.Fatalf("devices = %+v", got.Devices)
	}
}

func TestLoadRegistryMissingIsEmpty(t *testing.T) {
	got, err := LoadRegistry(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("LoadRegistry missing: %v", err)
	}
	if len(got.Users) != 0 || len(got.Devices) != 0 {
		t.Fatal("missing file should yield an empty registry")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./provision/ -run TestRegistry -v`
Expected: FAIL — `undefined: Registry` / `SaveRegistry` (or build error from the removed FileStore — acceptable for this task; Task 4 restores it).

- [ ] **Step 3: Write the implementation**

Replace `core/provision/registry.go` with:
```go
package provision

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// User is a registry user that owns devices and holds the enrollment credential.
type User struct {
	Handle       string    `json:"handle"`
	ID           string    `json:"id"`             // 16-byte UUIDv4, canonical hex; backs enroll tokens
	EnrollPSKEnc string    `json:"enroll_psk_enc"` // AEAD(masterKey, enrollPSK)
	DeviceCap    int       `json:"device_cap"`
	EnrollOpen   bool      `json:"enroll_open"`
	Disabled     bool      `json:"disabled"`
	CreatedAt    time.Time `json:"created_at"`
}

// Device is the server-side registry record for one device (one WireGuard peer).
type Device struct {
	DeviceID   string    `json:"device_id"`
	User       string    `json:"user"`
	WGPublic   string    `json:"wg_public"`
	TunnelIP   string    `json:"tunnel_ip"`
	AuthPSKEnc string    `json:"auth_psk_enc"` // AEAD(masterKey, per-device PSK)
	CreatedAt  time.Time `json:"created_at"`
	Source     string    `json:"source"` // "admin" | "enroll"
}

// Registry is the on-disk registry: users and devices. Only *_psk_enc fields are
// secret (and encrypted); everything else is public.
type Registry struct {
	Users   []User   `json:"users"`
	Devices []Device `json:"devices"`
}

// LoadRegistry reads the registry JSON object. A missing or empty file yields an
// empty registry (not an error).
func LoadRegistry(path string) (Registry, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(data) == 0) {
		return Registry{}, nil
	}
	if err != nil {
		return Registry{}, err
	}
	var reg Registry
	if err := json.Unmarshal(data, &reg); err != nil {
		return Registry{}, fmt.Errorf("provision: parse registry %q: %w", path, err)
	}
	return reg, nil
}

// SaveRegistry writes reg atomically (temp file + rename), 0600 (it contains
// encrypted PSKs).
func SaveRegistry(path string, reg Registry) error {
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ParseDeviceID decodes a canonical (hyphenated) or bare hex UUID into 16 bytes.
func ParseDeviceID(s string) ([16]byte, error) {
	clean := strings.ReplaceAll(s, "-", "")
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return [16]byte{}, err
	}
	if len(raw) != 16 {
		return [16]byte{}, fmt.Errorf("provision: device id is %d bytes, want 16", len(raw))
	}
	var id [16]byte
	copy(id[:], raw)
	return id, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./provision/ -run TestRegistry -v 2>&1 | tail -20`
Expected: the registry tests PASS. (Other provision tests / the package build may fail until Task 4 restores `FileStore` and Task 5 reworks `Generate` — that is expected mid-rework; do not fix them here.)

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/provision/registry.go core/provision/registry_test.go
git commit -m "feat(provision): user/device registry model (object form)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Read-write FileStore

**Files:** Create `core/provision/store.go`, `core/provision/store_test.go`.

- [ ] **Step 1: Write the failing test**

Create `core/provision/store_test.go`:
```go
package provision

import (
	"path/filepath"
	"strings"
	"testing"
)

func newTestStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.json")
	c, err := NewCipherFromHex(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	fs, err := NewFileStore(path, c)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return fs, path
}

func TestFileStoreAddUserAndDevice(t *testing.T) {
	fs, path := newTestStore(t)
	u, _, err := fs.AddUser("alice")
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if u.DeviceCap != 5 || !u.EnrollOpen {
		t.Fatalf("defaults: cap=%d open=%v", u.DeviceCap, u.EnrollOpen)
	}
	wg, _ := GeneratePrivateKeyHex(t)
	dev := Device{DeviceID: "22222222-2222-4222-8222-222222222222", User: "alice",
		WGPublic: wg, TunnelIP: "10.100.0.2", Source: "admin"}
	psk := []byte("device-psk-bytes")
	if err := fs.AddDevice(dev, psk); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}

	// Lookup decrypts the per-device PSK (authgate.DeviceStore behavior).
	id, _ := ParseDeviceID(dev.DeviceID)
	got, ok := fs.Lookup(id)
	if !ok || string(got) != string(psk) {
		t.Fatalf("Lookup = %q,%v want %q", got, ok, psk)
	}
	if _, ok := fs.WGPublicKey(id); !ok {
		t.Fatal("WGPublicKey missing")
	}
	rec, ok := fs.Device(id)
	if !ok || rec.TunnelIP != "10.100.0.2" {
		t.Fatalf("Device = %+v,%v", rec, ok)
	}

	// Persisted across reload.
	c, _ := NewCipherFromHex(strings.Repeat("ab", 32))
	fs2, err := NewFileStore(path, c)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got2, ok := fs2.Lookup(id); !ok || string(got2) != string(psk) {
		t.Fatalf("reloaded Lookup = %q,%v", got2, ok)
	}
}

func TestFileStoreEnrollPSKAndCap(t *testing.T) {
	fs, _ := newTestStore(t)
	u, enrollPSK, err := fs.AddUser("bob")
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	uid, _ := ParseDeviceID(u.ID)
	got, ok := fs.EnrollPSK(uid)
	if !ok || string(got) != string(enrollPSK) {
		t.Fatalf("EnrollPSK = %q,%v want the minted secret", got, ok)
	}
	if n := fs.DeviceCount("bob"); n != 0 {
		t.Fatalf("device count = %d, want 0", n)
	}
}

func TestFileStoreRemoveDevice(t *testing.T) {
	fs, _ := newTestStore(t)
	if _, _, err := fs.AddUser("alice"); err != nil {
		t.Fatal(err)
	}
	wg, _ := GeneratePrivateKeyHex(t)
	dev := Device{DeviceID: "22222222-2222-4222-8222-222222222222", User: "alice",
		WGPublic: wg, TunnelIP: "10.100.0.2", Source: "admin"}
	if err := fs.AddDevice(dev, []byte("psk")); err != nil {
		t.Fatal(err)
	}
	if err := fs.RemoveDevice(dev.DeviceID); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}
	id, _ := ParseDeviceID(dev.DeviceID)
	if _, ok := fs.Lookup(id); ok {
		t.Fatal("device still present after removal")
	}
}

func TestFileStoreDuplicateUser(t *testing.T) {
	fs, _ := newTestStore(t)
	if _, _, err := fs.AddUser("alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fs.AddUser("alice"); err == nil {
		t.Fatal("expected duplicate user error")
	}
}
```

Also add this test helper at the end of `core/provision/store_test.go`:
```go
// GeneratePrivateKeyHex returns a fresh WG public key hex for tests.
func GeneratePrivateKeyHex(t *testing.T) (string, string) {
	t.Helper()
	k, err := genWGKeyHexForTest()
	if err != nil {
		t.Fatalf("wg key: %v", err)
	}
	return k, k
}
```

(`genWGKeyHexForTest` is defined in the implementation file below so it is shared.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./provision/ -run TestFileStore -v`
Expected: FAIL — `undefined: NewFileStore` / `AddUser` etc.

- [ ] **Step 3: Write the implementation**

Create `core/provision/store.go`:
```go
package provision

import (
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/g00dvin/gvpn/core/wgengine"
)

// FileStore is a read-write, mutex-guarded registry persisted to a JSON file. It
// decrypts per-device PSKs in memory so it satisfies authgate.DeviceStore; the
// master-key cipher is held in memory only.
type FileStore struct {
	path   string
	cipher *Cipher

	mu  sync.RWMutex
	reg Registry
}

// NewFileStore loads (or creates an empty) registry at path, using c to decrypt
// secrets on read and encrypt on write.
func NewFileStore(path string, c *Cipher) (*FileStore, error) {
	reg, err := LoadRegistry(path)
	if err != nil {
		return nil, err
	}
	return &FileStore{path: path, cipher: c, reg: reg}, nil
}

// Lookup implements authgate.DeviceStore: it returns the device's decrypted PSK.
func (s *FileStore) Lookup(deviceID [16]byte) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.reg.Devices {
		id, err := ParseDeviceID(d.DeviceID)
		if err != nil || id != deviceID {
			continue
		}
		psk, err := s.cipher.Open(d.AuthPSKEnc)
		if err != nil {
			return nil, false
		}
		return psk, true
	}
	return nil, false
}

// EnrollPSK returns the decrypted enrollment PSK for the user with the given
// 16-byte user id.
func (s *FileStore) EnrollPSK(userID [16]byte) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.reg.Users {
		id, err := ParseDeviceID(u.ID)
		if err != nil || id != userID || u.Disabled {
			continue
		}
		psk, err := s.cipher.Open(u.EnrollPSKEnc)
		if err != nil {
			return nil, false
		}
		return psk, true
	}
	return nil, false
}

// WGPublicKey returns the device's registered WireGuard public key.
func (s *FileStore) WGPublicKey(deviceID [16]byte) (wgengine.Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.reg.Devices {
		id, err := ParseDeviceID(d.DeviceID)
		if err != nil || id != deviceID {
			continue
		}
		k, err := ParseKey(d.WGPublic)
		if err != nil {
			return wgengine.Key{}, false
		}
		return k, true
	}
	return wgengine.Key{}, false
}

// Device returns the device record (public fields).
func (s *FileStore) Device(deviceID [16]byte) (Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.reg.Devices {
		if id, err := ParseDeviceID(d.DeviceID); err == nil && id == deviceID {
			return d, true
		}
	}
	return Device{}, false
}

// User returns the user record by handle.
func (s *FileStore) User(handle string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.reg.Users {
		if u.Handle == handle {
			return u, true
		}
	}
	return User{}, false
}

// DeviceCount returns how many devices a user owns.
func (s *FileStore) DeviceCount(handle string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, d := range s.reg.Devices {
		if d.User == handle {
			n++
		}
	}
	return n
}

// UsedIPs returns the tunnel IPs currently allocated (for AllocateIP).
func (s *FileStore) UsedIPs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ips := make([]string, 0, len(s.reg.Devices))
	for _, d := range s.reg.Devices {
		ips = append(ips, d.TunnelIP)
	}
	return ips
}

// AddUser creates a user with default guardrails (cap 5, enrollment open),
// mints a 16-byte user id and a random enroll PSK, persists, and returns the
// user plus the plaintext enroll PSK (the caller emits it; it is not stored
// plaintext).
func (s *FileStore) AddUser(handle string) (User, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.reg.Users {
		if u.Handle == handle {
			return User{}, nil, fmt.Errorf("provision: user %q already exists", handle)
		}
	}
	uid, err := NewDeviceID()
	if err != nil {
		return User{}, nil, err
	}
	enrollPSK := make([]byte, authPSKSize)
	if _, err := io.ReadFull(rand.Reader, enrollPSK); err != nil {
		return User{}, nil, err
	}
	enc, err := s.cipher.Seal(enrollPSK)
	if err != nil {
		return User{}, nil, err
	}
	u := User{
		Handle: handle, ID: uid.String(), EnrollPSKEnc: enc,
		DeviceCap: 5, EnrollOpen: true, CreatedAt: time.Now().UTC(),
	}
	s.reg.Users = append(s.reg.Users, u)
	if err := SaveRegistry(s.path, s.reg); err != nil {
		s.reg.Users = s.reg.Users[:len(s.reg.Users)-1]
		return User{}, nil, err
	}
	return u, enrollPSK, nil
}

// RemoveUser deletes a user and all of its devices.
func (s *FileStore) RemoveUser(handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	users := s.reg.Users[:0:0]
	found := false
	for _, u := range s.reg.Users {
		if u.Handle == handle {
			found = true
			continue
		}
		users = append(users, u)
	}
	if !found {
		return fmt.Errorf("provision: user %q not found", handle)
	}
	devices := s.reg.Devices[:0:0]
	for _, d := range s.reg.Devices {
		if d.User != handle {
			devices = append(devices, d)
		}
	}
	prevU, prevD := s.reg.Users, s.reg.Devices
	s.reg.Users, s.reg.Devices = users, devices
	if err := SaveRegistry(s.path, s.reg); err != nil {
		s.reg.Users, s.reg.Devices = prevU, prevD
		return err
	}
	return nil
}

// AddDevice encrypts pskPlain into the record and persists it, rejecting a
// duplicate DeviceID or an unknown user.
func (s *FileStore) AddDevice(d Device, pskPlain []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	userOK := false
	for _, u := range s.reg.Users {
		if u.Handle == d.User {
			userOK = true
			break
		}
	}
	if !userOK {
		return fmt.Errorf("provision: unknown user %q", d.User)
	}
	for _, e := range s.reg.Devices {
		if e.DeviceID == d.DeviceID {
			return fmt.Errorf("provision: device %s already registered", d.DeviceID)
		}
	}
	enc, err := s.cipher.Seal(pskPlain)
	if err != nil {
		return err
	}
	d.AuthPSKEnc = enc
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	}
	s.reg.Devices = append(s.reg.Devices, d)
	if err := SaveRegistry(s.path, s.reg); err != nil {
		s.reg.Devices = s.reg.Devices[:len(s.reg.Devices)-1]
		return err
	}
	return nil
}

// RemoveDevice deletes a device by DeviceID.
func (s *FileStore) RemoveDevice(deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.reg.Devices[:0:0]
	found := false
	for _, d := range s.reg.Devices {
		if d.DeviceID == deviceID {
			found = true
			continue
		}
		out = append(out, d)
	}
	if !found {
		return fmt.Errorf("provision: device %s not found", deviceID)
	}
	prev := s.reg.Devices
	s.reg.Devices = out
	if err := SaveRegistry(s.path, s.reg); err != nil {
		s.reg.Devices = prev
		return err
	}
	return nil
}

// genWGKeyHexForTest is a small helper used by store_test.go.
func genWGKeyHexForTest() (string, error) {
	k, err := wgengine.GeneratePrivateKey()
	if err != nil {
		return "", err
	}
	return k.PublicKey().Hex(), nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./provision/ -run 'TestFileStore|TestRegistry|TestCipher|TestAllocateIP' -v`
Expected: PASS. (The package still won't fully build until Task 5 reworks `Generate`/`Bundle`; that's fine — these `-run` targets compile against the new files.) Note: if the package fails to compile because `provision.go` still references the old `Device` fields, proceed to Task 5 which fixes it; you may run Task 5 immediately after.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/provision/store.go core/provision/store_test.go
git commit -m "feat(provision): read-write FileStore (users, devices, encrypted PSKs)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Generate / Material / Bundle rework

**Files:** Rewrite `core/provision/provision.go` and `core/provision/provision_test.go`.

- [ ] **Step 1: Write the failing test**

Replace `core/provision/provision_test.go` with:
```go
package provision

import (
	"strings"
	"testing"

	"github.com/g00dvin/gvpn/core/wgengine"
)

func TestGenerateProducesMatchingBundleAndMaterial(t *testing.T) {
	srvPriv, _ := wgengine.GeneratePrivateKey()
	b, m, err := Generate("alice", "10.100.0.2", GenerateParams{
		ServerWGPublicKey: srvPriv.PublicKey(),
		ServerEndpoint:    "vpn.example.com:443",
		ServerName:        "vpn.example.com",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if b.DeviceID != m.DeviceID || b.TunnelIP != "10.100.0.2" || m.User != "alice" {
		t.Fatalf("bundle/material mismatch: %+v / %+v", b, m)
	}
	// The bundle's private key must match the material's public key.
	priv, err := ParseKey(b.WGPrivateKey)
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	if priv.PublicKey().Hex() != m.WGPublic {
		t.Fatal("bundle private key does not match material public key")
	}
	if len(m.AuthPSK) != authPSKSize {
		t.Fatalf("auth psk len = %d", len(m.AuthPSK))
	}
}

func TestMaterialRecordEncryptsPSK(t *testing.T) {
	c, _ := NewCipherFromHex(strings.Repeat("ab", 32))
	_, m, _ := Generate("alice", "10.100.0.2", GenerateParams{ServerEndpoint: "h:443", ServerName: "h"})
	rec, err := m.Record(c, "admin")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if rec.AuthPSKEnc == "" || strings.Contains(rec.AuthPSKEnc, string(m.AuthPSK)) {
		t.Fatal("record PSK not encrypted")
	}
	got, err := c.Open(rec.AuthPSKEnc)
	if err != nil || string(got) != string(m.AuthPSK) {
		t.Fatalf("decrypt mismatch: %v", err)
	}
	if rec.Source != "admin" || rec.User != "alice" || rec.TunnelIP != "10.100.0.2" {
		t.Fatalf("record fields: %+v", rec)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./provision/ -run 'TestGenerate|TestMaterial' -v`
Expected: FAIL — `Generate` signature mismatch / `undefined: Material`.

- [ ] **Step 3: Write the implementation**

Replace `core/provision/provision.go` with:
```go
// Package provision mints gvpn credentials. It manages a user/device registry
// (FileStore), encrypts secrets at rest (Cipher), allocates tunnel IPs
// (AllocateIP), and emits enrollment bundles. Pure Go, no cgo.
package provision

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/g00dvin/gvpn/core/wgengine"
)

// authPSKSize is the size in bytes of AUTH / enrollment pre-shared keys.
const authPSKSize = 32

// DeviceID is a 16-byte UUIDv4 identifier (used for both device and user ids).
type DeviceID [16]byte

// NewDeviceID generates a random UUIDv4.
func NewDeviceID() (DeviceID, error) {
	var id DeviceID
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return DeviceID{}, err
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id, nil
}

// String returns the canonical 8-4-4-4-12 hyphenated hex UUID.
func (d DeviceID) String() string {
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(d[0:4]), hex.EncodeToString(d[4:6]),
		hex.EncodeToString(d[6:8]), hex.EncodeToString(d[8:10]),
		hex.EncodeToString(d[10:16]))
}

// Bundle is the client-side device bundle (contains secrets; store 0600).
type Bundle struct {
	DeviceID          string `json:"device_id"`
	AuthPSK           string `json:"auth_psk"`
	WGPrivateKey      string `json:"wg_private_key"`
	TunnelIP          string `json:"tunnel_ip"`
	ServerWGPublicKey string `json:"server_wg_public_key"`
	ServerEndpoint    string `json:"server_endpoint"`
	ServerName        string `json:"server_name"`
	ServerCAPEM       string `json:"server_ca_pem,omitempty"`
}

// Material is the freshly minted, still-plaintext result of Generate, ready to
// be turned into an encrypted registry Device via Record.
type Material struct {
	DeviceID string
	User     string
	TunnelIP string
	WGPublic string
	AuthPSK  []byte
}

// GenerateParams holds the server coordinates embedded into a bundle.
type GenerateParams struct {
	ServerWGPublicKey wgengine.Key
	ServerEndpoint    string
	ServerName        string
	ServerCAPEM       string
}

// Generate mints a device for user with the given tunnel IP: a UUIDv4 DeviceID,
// a random AUTH PSK, and a WireGuard keypair. It returns the client Bundle and
// the plaintext Material (for the server registry).
func Generate(user, tunnelIP string, p GenerateParams) (Bundle, Material, error) {
	id, err := NewDeviceID()
	if err != nil {
		return Bundle{}, Material{}, err
	}
	psk := make([]byte, authPSKSize)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		return Bundle{}, Material{}, err
	}
	wgPriv, err := wgengine.GeneratePrivateKey()
	if err != nil {
		return Bundle{}, Material{}, err
	}
	idStr := id.String()
	bundle := Bundle{
		DeviceID:          idStr,
		AuthPSK:           hex.EncodeToString(psk),
		WGPrivateKey:      wgPriv.Hex(),
		TunnelIP:          tunnelIP,
		ServerWGPublicKey: p.ServerWGPublicKey.Hex(),
		ServerEndpoint:    p.ServerEndpoint,
		ServerName:        p.ServerName,
		ServerCAPEM:       p.ServerCAPEM,
	}
	mat := Material{
		DeviceID: idStr, User: user, TunnelIP: tunnelIP,
		WGPublic: wgPriv.PublicKey().Hex(), AuthPSK: psk,
	}
	return bundle, mat, nil
}

// Record turns Material into an encrypted registry Device. source is "admin" or
// "enroll".
func (m Material) Record(c *Cipher, source string) (Device, error) {
	enc, err := c.Seal(m.AuthPSK)
	if err != nil {
		return Device{}, err
	}
	return Device{
		DeviceID: m.DeviceID, User: m.User, WGPublic: m.WGPublic,
		TunnelIP: m.TunnelIP, AuthPSKEnc: enc, Source: source,
	}, nil
}

// Marshal serializes the bundle as indented JSON.
func (b Bundle) Marshal() ([]byte, error) { return json.MarshalIndent(b, "", "  ") }

// ParseBundle deserializes a bundle from JSON.
func ParseBundle(data []byte) (Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return Bundle{}, fmt.Errorf("provision: parse bundle: %w", err)
	}
	return b, nil
}

// ParseKey decodes a 32-byte hex WireGuard key.
func ParseKey(s string) (wgengine.Key, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return wgengine.Key{}, err
	}
	if len(raw) != 32 {
		return wgengine.Key{}, fmt.Errorf("provision: key is %d bytes, want 32", len(raw))
	}
	var k wgengine.Key
	copy(k[:], raw)
	return k, nil
}
```

- [ ] **Step 4: Run the full provision package**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./provision/ -v 2>&1 | tail -30`
Expected: the whole `provision` package builds and PASSES (Tasks 1–5 together). Also `/home/goodvin/.local/go/bin/go vet ./provision/`.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/provision/provision.go core/provision/provision_test.go
git commit -m "feat(provision): Generate/Material rework (per-user, tunnel IP, encrypted record)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Enrollment bundle URI

**Files:** Create `core/provision/bundle.go`, `core/provision/bundle_test.go`.

- [ ] **Step 1: Write the failing test**

Create `core/provision/bundle_test.go`:
```go
package provision

import "testing"

func TestEnrollURIRoundTrip(t *testing.T) {
	in := EnrollLink{
		User: "alice", EnrollPSK: []byte("0123456789abcdef0123456789abcdef"),
		Host: "vpn.example.com:443", ServerName: "vpn.example.com", CertFP: "sha256fp",
	}
	uri := in.URI()
	if uri[:14] != "gvpn://enroll?" {
		t.Fatalf("uri prefix = %q", uri[:14])
	}
	out, err := ParseEnrollURI(uri)
	if err != nil {
		t.Fatalf("ParseEnrollURI: %v", err)
	}
	if out.User != in.User || out.Host != in.Host || out.ServerName != in.ServerName ||
		out.CertFP != in.CertFP || string(out.EnrollPSK) != string(in.EnrollPSK) {
		t.Fatalf("round trip mismatch: %+v vs %+v", out, in)
	}
}

func TestParseEnrollURIRejectsNonGvpn(t *testing.T) {
	if _, err := ParseEnrollURI("https://example.com/enroll"); err == nil {
		t.Fatal("expected scheme error")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./provision/ -run TestEnrollURI -v`
Expected: FAIL — `undefined: EnrollLink`.

- [ ] **Step 3: Write the implementation**

Create `core/provision/bundle.go`:
```go
package provision

import (
	"encoding/base64"
	"fmt"
	"net/url"
)

// EnrollLink is the data carried by an enrollment bundle: the user-level
// credential plus how to reach the server. It is rendered as a gvpn://enroll URI.
type EnrollLink struct {
	User       string
	EnrollPSK  []byte
	Host       string // host:port
	ServerName string // TLS SNI
	CertFP     string // optional base64/hex GOST cert fingerprint to pin
}

// URI renders the canonical gvpn://enroll?... deep link.
func (l EnrollLink) URI() string {
	q := url.Values{}
	q.Set("u", l.User)
	q.Set("psk", base64.RawURLEncoding.EncodeToString(l.EnrollPSK))
	q.Set("h", l.Host)
	q.Set("sni", l.ServerName)
	if l.CertFP != "" {
		q.Set("caf", l.CertFP)
	}
	return "gvpn://enroll?" + q.Encode()
}

// ParseEnrollURI parses a gvpn://enroll?... deep link.
func ParseEnrollURI(s string) (EnrollLink, error) {
	u, err := url.Parse(s)
	if err != nil {
		return EnrollLink{}, fmt.Errorf("provision: parse enroll uri: %w", err)
	}
	if u.Scheme != "gvpn" || u.Host != "enroll" {
		return EnrollLink{}, fmt.Errorf("provision: not a gvpn://enroll uri: %q", s)
	}
	q := u.Query()
	psk, err := base64.RawURLEncoding.DecodeString(q.Get("psk"))
	if err != nil {
		return EnrollLink{}, fmt.Errorf("provision: enroll psk: %w", err)
	}
	return EnrollLink{
		User: q.Get("u"), EnrollPSK: psk, Host: q.Get("h"),
		ServerName: q.Get("sni"), CertFP: q.Get("caf"),
	}, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./provision/ -run TestEnrollURI -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./provision/`.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/provision/bundle.go core/provision/bundle_test.go
git commit -m "feat(provision): canonical gvpn://enroll bundle URI

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: QR + terminal emission

**Files:** Create `core/provision/emit.go`, `core/provision/emit_test.go`. Adds the `github.com/skip2/go-qrcode` dependency.

- [ ] **Step 1: Add the dependency**

Run:
```bash
cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go get github.com/skip2/go-qrcode@v0.0.0-20200617195104-da1b6568686e
```
Expected: `go.mod`/`go.sum` updated.

- [ ] **Step 2: Write the failing test**

Create `core/provision/emit_test.go`:
```go
package provision

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteQRPNG(t *testing.T) {
	p := filepath.Join(t.TempDir(), "code.png")
	if err := WriteQRPNG("gvpn://enroll?u=alice", p, 256); err != nil {
		t.Fatalf("WriteQRPNG: %v", err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read png: %v", err)
	}
	if len(data) < 8 || string(data[1:4]) != "PNG" {
		t.Fatal("output is not a PNG")
	}
}

func TestTerminalQR(t *testing.T) {
	s, err := TerminalQR("gvpn://enroll?u=alice")
	if err != nil {
		t.Fatalf("TerminalQR: %v", err)
	}
	if !strings.Contains(s, "\n") || len(s) < 10 {
		t.Fatal("terminal QR looks empty")
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./provision/ -run 'TestWriteQRPNG|TestTerminalQR' -v`
Expected: FAIL — `undefined: WriteQRPNG`.

- [ ] **Step 4: Write the implementation**

Create `core/provision/emit.go`:
```go
package provision

import (
	qrcode "github.com/skip2/go-qrcode"
)

// WriteQRPNG renders content as a QR-code PNG of the given pixel size.
func WriteQRPNG(content, path string, size int) error {
	return qrcode.WriteFile(content, qrcode.Medium, size, path)
}

// TerminalQR renders content as a compact half-block QR for a terminal.
func TerminalQR(content string) (string, error) {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return "", err
	}
	return q.ToSmallString(false), nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./provision/ -run 'TestWriteQRPNG|TestTerminalQR' -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./provision/`.

- [ ] **Step 6: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/provision/emit.go core/provision/emit_test.go core/go.mod core/go.sum
git commit -m "feat(provision): QR + terminal enrollment-link emission

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 8: gvpn-provision CLI (user/device subcommands)

**Files:** Rewrite `core/cmd/gvpn-provision/main.go` and `core/cmd/gvpn-provision/main_test.go`.

The CLI dispatches subcommands: `user add|list|remove`, `device add|list|revoke`. It loads the master key (`GVPN_MASTER_KEY` / `--master-key-file`) and operates on the registry directly (bootstrap path; the running server owns the registry at runtime — out of scope here). `user add` emits the enrollment bundle as file/link/QR.

- [ ] **Step 1: Write the failing test**

Replace `core/cmd/gvpn-provision/main_test.go` with:
```go
package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/g00dvin/gvpn/core/provision"
)

func envKey(t *testing.T) { t.Helper(); t.Setenv("GVPN_MASTER_KEY", strings.Repeat("ab", 32)) }

func TestUserAddEmitsBundleAndRegisters(t *testing.T) {
	envKey(t)
	dir := t.TempDir()
	reg := filepath.Join(dir, "registry.json")
	out := filepath.Join(dir, "alice.gvpn")
	var buf bytes.Buffer
	err := run([]string{
		"user", "add", "alice",
		"--registry", reg, "--host", "vpn.example.com:443", "--sni", "vpn.example.com",
		"--out", out,
	}, &buf)
	if err != nil {
		t.Fatalf("user add: %v", err)
	}
	if !strings.Contains(buf.String(), "gvpn://enroll?") {
		t.Fatalf("output missing deep link: %s", buf.String())
	}
	c, _ := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	fs, err := provision.NewFileStore(reg, c)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, ok := fs.User("alice"); !ok {
		t.Fatal("alice not registered")
	}
}

func TestDeviceAddAllocatesIPAndRegisters(t *testing.T) {
	envKey(t)
	dir := t.TempDir()
	reg := filepath.Join(dir, "registry.json")
	var buf bytes.Buffer
	if err := run([]string{"user", "add", "bob", "--registry", reg,
		"--host", "h:443", "--sni", "h", "--out", filepath.Join(dir, "bob.gvpn")}, &buf); err != nil {
		t.Fatalf("user add: %v", err)
	}
	buf.Reset()
	srvPriv, _ := provision.ParseKey(strings.Repeat("cd", 32))
	_ = srvPriv
	err := run([]string{"device", "add", "--user", "bob", "--registry", reg,
		"--server-wg-pubkey", strings.Repeat("cd", 32), "--endpoint", "h:443", "--server-name", "h",
		"--subnet", "10.100.0.0/24", "--out", filepath.Join(dir, "dev.json")}, &buf)
	if err != nil {
		t.Fatalf("device add: %v", err)
	}
	if !strings.Contains(buf.String(), "10.100.0.2") {
		t.Fatalf("expected allocated IP 10.100.0.2 in output: %s", buf.String())
	}
}

func TestUserAddRequiresMasterKey(t *testing.T) {
	t.Setenv("GVPN_MASTER_KEY", "")
	var buf bytes.Buffer
	err := run([]string{"user", "add", "alice", "--registry",
		filepath.Join(t.TempDir(), "r.json"), "--host", "h:443", "--sni", "h"}, &buf)
	if err == nil {
		t.Fatal("expected master-key error")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./cmd/gvpn-provision/ -run 'TestUserAdd|TestDeviceAdd' -v`
Expected: FAIL — current `run` has the old flat-flag signature.

- [ ] **Step 3: Write the implementation**

Replace `core/cmd/gvpn-provision/main.go` with:
```go
// Command gvpn-provision manages the gvpn user/device registry: it creates users
// (emitting an enrollment bundle) and admin-provisions devices. It is the
// bootstrap path; while gvpn-server runs, the server owns the registry.
//
// Master key: GVPN_MASTER_KEY (64 hex chars) or --master-key-file.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/g00dvin/gvpn/core/provision"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "gvpn-provision:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: gvpn-provision <user|device> <add|list|remove|revoke> [flags]")
	}
	group, sub, rest := args[0], args[1], args[2:]
	switch group {
	case "user":
		switch sub {
		case "add":
			return userAdd(rest, out)
		case "list":
			return userList(rest, out)
		case "remove":
			return userRemove(rest, out)
		}
	case "device":
		switch sub {
		case "add":
			return deviceAdd(rest, out)
		case "list":
			return deviceList(rest, out)
		case "revoke":
			return deviceRevoke(rest, out)
		}
	}
	return fmt.Errorf("unknown command %q %q", group, sub)
}

func openStore(registry, masterKeyFile string) (*provision.FileStore, error) {
	key, err := provision.LoadMasterKey(masterKeyFile)
	if err != nil {
		return nil, err
	}
	c, err := provision.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return provision.NewFileStore(registry, c)
}

func userAdd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("user add", flag.ContinueOnError)
	fs.SetOutput(out)
	registry := fs.String("registry", "registry.json", "registry file")
	masterKeyFile := fs.String("master-key-file", "", "master key file (or GVPN_MASTER_KEY)")
	host := fs.String("host", "", "server host:port (required)")
	sni := fs.String("sni", "", "server TLS name (required)")
	caf := fs.String("cert-fp", "", "GOST cert fingerprint to pin (optional)")
	outFile := fs.String("out", "", "write the .gvpn bundle file here (optional)")
	qrFile := fs.String("qr", "", "write a QR PNG here (optional)")
	handleArg := ""
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		handleArg, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if handleArg == "" || *host == "" || *sni == "" {
		return fmt.Errorf("usage: user add <handle> --host <h:port> --sni <name> [--out f] [--qr f]")
	}
	store, err := openStore(*registry, *masterKeyFile)
	if err != nil {
		return err
	}
	_, enrollPSK, err := store.AddUser(handleArg)
	if err != nil {
		return err
	}
	link := provision.EnrollLink{User: handleArg, EnrollPSK: enrollPSK, Host: *host, ServerName: *sni, CertFP: *caf}
	uri := link.URI()
	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(uri+"\n"), 0o600); err != nil {
			return fmt.Errorf("write bundle: %w", err)
		}
	}
	if *qrFile != "" {
		if err := provision.WriteQRPNG(uri, *qrFile, 320); err != nil {
			return fmt.Errorf("write qr: %w", err)
		}
	}
	term, err := provision.TerminalQR(uri)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "created user %q\n%s\n%s\n", handleArg, uri, term)
	if *outFile != "" {
		fmt.Fprintf(out, "bundle: %s\n", *outFile)
	}
	if *qrFile != "" {
		fmt.Fprintf(out, "qr:     %s\n", *qrFile)
	}
	return nil
}

func userList(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("user list", flag.ContinueOnError)
	fs.SetOutput(out)
	registry := fs.String("registry", "registry.json", "registry file")
	masterKeyFile := fs.String("master-key-file", "", "master key file (or GVPN_MASTER_KEY)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := openStore(*registry, *masterKeyFile)
	if err != nil {
		return err
	}
	reg, err := provision.LoadRegistry(*registry)
	if err != nil {
		return err
	}
	for _, u := range reg.Users {
		fmt.Fprintf(out, "%s  devices=%d cap=%d enroll_open=%v disabled=%v\n",
			u.Handle, store.DeviceCount(u.Handle), u.DeviceCap, u.EnrollOpen, u.Disabled)
	}
	return nil
}

func userRemove(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("user remove", flag.ContinueOnError)
	fs.SetOutput(out)
	registry := fs.String("registry", "registry.json", "registry file")
	masterKeyFile := fs.String("master-key-file", "", "master key file (or GVPN_MASTER_KEY)")
	handleArg := ""
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		handleArg, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if handleArg == "" {
		return fmt.Errorf("usage: user remove <handle>")
	}
	store, err := openStore(*registry, *masterKeyFile)
	if err != nil {
		return err
	}
	if err := store.RemoveUser(handleArg); err != nil {
		return err
	}
	fmt.Fprintf(out, "removed user %q (and its devices)\n", handleArg)
	return nil
}

func deviceAdd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("device add", flag.ContinueOnError)
	fs.SetOutput(out)
	registry := fs.String("registry", "registry.json", "registry file")
	masterKeyFile := fs.String("master-key-file", "", "master key file (or GVPN_MASTER_KEY)")
	user := fs.String("user", "", "owning user handle (required)")
	serverPub := fs.String("server-wg-pubkey", "", "server WG public key hex (required)")
	endpoint := fs.String("endpoint", "", "server endpoint host:port (required)")
	serverName := fs.String("server-name", "", "server TLS name (required)")
	subnet := fs.String("subnet", "10.100.0.0/24", "tunnel subnet for IP allocation")
	caPath := fs.String("ca", "", "server CA PEM path (optional)")
	outFile := fs.String("out", "", "client bundle output file (default <device-id>.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" || *serverPub == "" || *endpoint == "" || *serverName == "" {
		return fmt.Errorf("--user, --server-wg-pubkey, --endpoint and --server-name are required")
	}
	pub, err := provision.ParseKey(*serverPub)
	if err != nil {
		return fmt.Errorf("invalid --server-wg-pubkey: %w", err)
	}
	prefix, err := netip.ParsePrefix(*subnet)
	if err != nil {
		return fmt.Errorf("invalid --subnet: %w", err)
	}
	store, err := openStore(*registry, *masterKeyFile)
	if err != nil {
		return err
	}
	if _, ok := store.User(*user); !ok {
		return fmt.Errorf("unknown user %q (create it with: user add)", *user)
	}
	used := make([]netip.Addr, 0)
	for _, s := range store.UsedIPs() {
		if a, err := netip.ParseAddr(s); err == nil {
			used = append(used, a)
		}
	}
	ip, err := provision.AllocateIP(used, prefix)
	if err != nil {
		return err
	}
	var caPEM string
	if *caPath != "" {
		raw, err := os.ReadFile(*caPath)
		if err != nil {
			return fmt.Errorf("read --ca: %w", err)
		}
		caPEM = string(raw)
	}
	bundle, mat, err := provision.Generate(*user, ip.String(), provision.GenerateParams{
		ServerWGPublicKey: pub, ServerEndpoint: *endpoint, ServerName: *serverName, ServerCAPEM: caPEM,
	})
	if err != nil {
		return err
	}
	rec, err := mat.Record(nil, "admin") // cipher injected below via AddDevice
	_ = rec
	if err := store.AddDevice(provision.Device{
		DeviceID: mat.DeviceID, User: mat.User, WGPublic: mat.WGPublic,
		TunnelIP: mat.TunnelIP, Source: "admin",
	}, mat.AuthPSK); err != nil {
		return err
	}
	dst := *outFile
	if dst == "" {
		dst = mat.DeviceID + ".json"
	}
	data, err := bundle.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}
	fmt.Fprintf(out, "provisioned device %s for %s\n  tunnel ip: %s\n  bundle:    %s\n",
		mat.DeviceID, *user, ip.String(), dst)
	return nil
}

func deviceList(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("device list", flag.ContinueOnError)
	fs.SetOutput(out)
	registry := fs.String("registry", "registry.json", "registry file")
	user := fs.String("user", "", "filter by user (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	reg, err := provision.LoadRegistry(*registry)
	if err != nil {
		return err
	}
	for _, d := range reg.Devices {
		if *user != "" && d.User != *user {
			continue
		}
		fmt.Fprintf(out, "%s  user=%s ip=%s source=%s\n", d.DeviceID, d.User, d.TunnelIP, d.Source)
	}
	return nil
}

func deviceRevoke(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("device revoke", flag.ContinueOnError)
	fs.SetOutput(out)
	registry := fs.String("registry", "registry.json", "registry file")
	masterKeyFile := fs.String("master-key-file", "", "master key file (or GVPN_MASTER_KEY)")
	idArg := ""
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		idArg, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if idArg == "" {
		return fmt.Errorf("usage: device revoke <device-id>")
	}
	store, err := openStore(*registry, *masterKeyFile)
	if err != nil {
		return err
	}
	if err := store.RemoveDevice(idArg); err != nil {
		return err
	}
	fmt.Fprintf(out, "revoked device %s\n", idArg)
	return nil
}
```

Note: the `rec, err := mat.Record(nil, "admin")` line above is dead (the store encrypts via `AddDevice`); **remove** the `rec`/`_ = rec` lines and the `Record` call when implementing — they are shown only to flag that `Record` is for the server enrollment path (Plan 11), not the CLI. The CLI builds the `Device` directly and lets `AddDevice` encrypt. Ensure the file compiles with no unused variables.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./cmd/gvpn-provision/ -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./cmd/gvpn-provision/`.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/cmd/gvpn-provision/main.go core/cmd/gvpn-provision/main_test.go
git commit -m "feat(provision): gvpn-provision user/device subcommands

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 9: Keep core/server green

The provision API changed (`Generate` signature, `NewFileStore` now needs a cipher, `Device` fields). `core/server/server.go` itself only calls `store.WGPublicKey` and uses `*provision.FileStore`, so it is unaffected — but `core/server/server_test.go` and `e2e_test.go` call `NewFileStore`/`Generate`/`AppendDevice` and must be updated.

**Files:** Modify `core/server/server_test.go`, `core/server/e2e_test.go`.

- [ ] **Step 1: See the breakage**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./server/ 2>&1 | tail -20`
Expected: build errors in the server tests (e.g. `not enough arguments in call to provision.NewFileStore`, `undefined: provision.AppendDevice`, `Generate` arg count).

- [ ] **Step 2: Update `server_test.go`**

In `core/server/server_test.go`, the unauthenticated-conn test builds an empty store. Replace the `provision.NewFileStore(...)` construction with a cipher-backed one:
```go
// at top of the test, after t.TempDir():
c, err := provision.NewCipherFromHex(strings.Repeat("ab", 32))
if err != nil {
	t.Fatalf("cipher: %v", err)
}
store, err := provision.NewFileStore(filepath.Join(t.TempDir(), "registry.json"), c)
if err != nil {
	t.Fatalf("NewFileStore: %v", err)
}
```
Add `"strings"` to the imports. (The rest of that test is unchanged; an empty registry still yields an unauthenticated-conn closure.)

- [ ] **Step 3: Update `e2e_test.go`**

In `core/server/e2e_test.go`, replace the provisioning section (`provision.Generate(...)`, `provision.AppendDevice(...)`, `provision.NewFileStore(...)`) with the new flow: create a cipher, a store, a user, then an admin device via the store. Replace that block with:
```go
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
```
Add `"strings"` to the imports. Keep the rest of the test (it already uses `bundle.AuthPSK`, `bundle.DeviceID`, `bundle.WGPrivateKey`, and `store` as the gate/WG store). The device's per-client `allowed_ip` is still `0.0.0.0/0` from `server.Config` defaults — the per-client server is unchanged in this plan.

- [ ] **Step 4: Verify the whole module builds and passes**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test -race ./provision/ ./cmd/gvpn-provision/ ./server/
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go build ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./...
```
Expected: all PASS / clean. (`gosttls` needs cgo; the rest is pure Go.)

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/server/server_test.go core/server/e2e_test.go
git commit -m "test(server): adapt to the new provision registry API

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 10: Final review + PR

**Files:** none (verification + PR only).

- [ ] **Step 1: Whole-repo verification**

```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test -race ./provision/ ./cmd/gvpn-provision/ ./server/
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test -race ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go build ./...
```
Expected: all PASS / clean.

- [ ] **Step 2: Confirm provision stays cgo-free**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go list -deps ./provision/ ./cmd/gvpn-provision/ | grep -iE 'gosttls|netstack|gvisor' || echo "OK: no cgo/netstack in provision graph"`
Expected: `OK`.

- [ ] **Step 3: Opus final code + security review** (controller dispatches a fresh Opus subagent)

Review focus: AEAD usage (random nonce, no key/PSK logging, ciphertext never reveals plaintext); master-key loading rejects bad sizes; `AllocateIP` boundaries (network/.1/broadcast reserved, exhaustion error, no off-by-one); `FileStore` concurrency (RWMutex; persistence rollback on save error; atomic rename); no plaintext PSK ever written to disk; duplicate user/device rejected; `RemoveUser` cascades devices; CLI master-key required; the registry format is internally consistent; `core/server` still green; `provision` stays cgo-free.

- [ ] **Step 4: Push and open PR** (trivial / `gh` — Haiku)

```bash
cd /home/goodvin/git/gvpn
git push -u origin feat/identity-registry
gh pr create --base main --head feat/identity-registry \
  --title "Identity & registry rework: users, devices, encrypted secrets, enrollment bundles" \
  --body "Reworks provisioning into a user→device model with secrets encrypted at rest, tunnel-IP allocation, a read-write registry, and a gvpn-provision CLI with user/device subcommands that emit enrollment bundles (file/deep-link/QR). First plan of the identity/enrollment/multiplexed-server/admin design (docs/superpowers/specs/2026-06-16-user-identity-enrollment-admin-design.md).

- AEAD (XChaCha20-Poly1305) cipher + master-key loading (GVPN_MASTER_KEY / key-file; never in config).
- AllocateIP: lowest free host in subnet (reserve network + .1 + broadcast).
- Registry{Users,Devices} object model; read-write, mutex-guarded, atomically-persisted FileStore that decrypts PSKs in memory (authgate.DeviceStore unchanged).
- Generate/Material rework (per-user, tunnel IP, encrypted record); gvpn://enroll bundle URI; QR (skip2/go-qrcode) + terminal emission.
- gvpn-provision: user add|list|remove, device add|list|revoke.
- core/server kept green (tests adapted; per-client server unchanged — it is replaced in a later plan).

Breaking: registry format changed (object, encrypted fields); dev registries are regenerated (no migration). Out of scope (next plans): AUTH token kind + enrollment exchange; multiplexed server + runtime enrollment writes; gvpn-server binary; admin web UI + share page.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

---

## Self-Review

**Spec coverage (design §4–§8, §15 Plan 9):** user/device model (Tasks 3–4), per-device + per-user enroll PSK encrypted at rest (Tasks 1, 4, 5), master key (Task 1), IPAM (Task 2), read-write persistent FileStore with lookups (Task 4), Generate/Material rework (Task 5), bundle URI + file/link/QR emission (Tasks 6–8), CLI user/device subcommands (Task 8), build-green for consumers (Task 9). The 16-byte user id is a stored UUID (`User.ID`), resolving design §16. EnrollPSK lookup by user id (Task 4) is provided for the Plan 10 authgate wiring. The AUTH token `kind`, the ENROLL exchange, runtime enrollment writes, the multiplexed server, and the admin UI are explicitly out of scope (later plans).

**Placeholder scan:** none — every step has full code. The one intentional call-out is the dead `mat.Record(nil, ...)` lines in Task 8 Step 3, flagged in a Note to be removed (they document that `Record` belongs to the server enrollment path, not the CLI). `Material.Record` is exercised by Task 5's test, so it is covered.

**Type consistency:** `Cipher.Seal(([]byte)) (string,error)` / `Open(string) ([]byte,error)`; `LoadMasterKey(keyFile string) ([]byte,error)`; `NewCipher([]byte)` / `NewCipherFromHex(string)`; `AllocateIP([]netip.Addr, netip.Prefix) (netip.Addr,error)`; `Registry{Users []User; Devices []Device}`; `NewFileStore(path string, c *Cipher)`; store methods `Lookup`/`EnrollPSK`/`WGPublicKey`/`Device`/`User`/`DeviceCount`/`UsedIPs`/`AddUser`(→`(User,[]byte,error)`)/`RemoveUser`/`AddDevice(Device,[]byte)`/`RemoveDevice`; `Generate(user,tunnelIP string, GenerateParams) (Bundle,Material,error)`; `Material.Record(*Cipher,string) (Device,error)`; `EnrollLink{...}.URI()` / `ParseEnrollURI`; `WriteQRPNG`/`TerminalQR`. `FileStore` satisfies `authgate.DeviceStore` via `Lookup(deviceID [16]byte) ([]byte,bool)` (unchanged). Server tests use the new `Generate`/`NewFileStore`/`AddUser`/`AddDevice` signatures (Task 9).
