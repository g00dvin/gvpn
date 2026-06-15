# Device Provisioning + Registry + `gvpn-provision` CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. Pure Go, no cgo.
>
> **Per-task model assignment (standing rule):**
> - **Sonnet** subagent — implements each code task (Tasks 1–3).
> - **Opus** (controller) — manages tasks, reviews each diff; dispatches a fresh **Opus** subagent for the final code + security review (Task 4).
> - **Haiku** subagent — `gh` push + PR (Task 4).

**Goal:** A `gvpn-provision` CLI (and its library) that mints a device: a UUIDv4 DeviceID, an AUTH pre-shared key, and a WireGuard keypair. It writes a **client bundle** (everything a client needs to connect) and appends a record to a **server device registry** that the server loads to authenticate devices (DeviceID → AUTH PSK) and to configure the WireGuard peer (DeviceID → WG public key).

**Architecture:** A new pure-Go `core/provision` package plus a `core/cmd/gvpn-provision` binary. `Generate` produces a `Bundle` (client side: DeviceID, AUTH PSK, WG private key, server WG public key, server endpoint/name, optional CA PEM) and a `Device` (server side: DeviceID, AUTH PSK, WG public key) sharing the same identity. The registry is a JSON file of `Device` records (0600). `FileStore` loads the registry and implements `authgate.DeviceStore` (so the server's auth gate uses it directly) plus a `WGPublicKey` lookup for the data path. WG keys reuse `core/wgengine` (`GeneratePrivateKey`/`PublicKey`/`Hex`); the AUTH PSK matches what `core/authgate` expects (an opaque secret keyed by DeviceID).

**Why now (sequencing):** the server assembly must resolve, per authenticated DeviceID, both the AUTH PSK *and* the client's WG public key — a persistent registry that only provisioning creates. Provisioning is therefore the prerequisite for the server plan (which is also where the WG-device-topology decision and the real TUN live).

**Tech Stack:** Go 1.24, stdlib (`crypto/rand`, `encoding/hex`, `encoding/json`, `flag`, `os`, `strings`). Reuses `core/wgengine` (Key helpers) and `core/authgate` (DeviceStore interface). Toolchain `/home/goodvin/.local/go/bin/go`. No cgo.

**Design reference:** `docs/superpowers/specs/2026-06-13-gvpn-transport-design.md` §6 (provisioning: `gvpn-provision` emits the device bundle and registers the peer; bundle = WG keypair, AUTH PSK, server endpoint, trust anchor, DeviceID).

---

## Conventions

- Toolchain: `/home/goodvin/.local/go/bin/go`. Run package tests with:
  `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./provision/ ./cmd/...`
- Branch `feat/provisioning` off `main` (already created). Work from `/home/goodvin/git/gvpn`.
- Commits end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Module path `github.com/g00dvin/gvpn/core`; import `github.com/g00dvin/gvpn/core/wgengine` and `github.com/g00dvin/gvpn/core/authgate`.
- **Secrets:** the client bundle (WG private key + PSK) and the registry (PSK) are sensitive — write both files with `0o600`. Never log PSK or key material; the CLI prints only the DeviceID and file paths.

## Existing APIs this plan builds on

- `core/wgengine`: `Key [32]byte`, `GeneratePrivateKey() (Key, error)`, `(Key).PublicKey() Key`, `(Key).Hex() string`.
- `core/authgate`: `DeviceStore interface { Lookup(deviceID [16]byte) (psk []byte, ok bool) }` — `FileStore` must satisfy this.

## File structure

```
core/provision/provision.go         DeviceID/UUID, Bundle, Device, GenerateParams, Generate, Bundle JSON
core/provision/provision_test.go
core/provision/registry.go          LoadRegistry, AppendDevice, FileStore (+ParseDeviceID, ParseKey)
core/provision/registry_test.go
core/cmd/gvpn-provision/main.go      CLI: run(args, out) + main
core/cmd/gvpn-provision/main_test.go
```

---

## Task 1: provision core (IDs, bundle, generate)

**Files:** Create `core/provision/provision.go`, `core/provision/provision_test.go`.

- [ ] **Step 1: Write the failing test**

Create `core/provision/provision_test.go`:
```go
package provision

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/g00dvin/gvpn/core/wgengine"
)

func TestNewDeviceIDIsUUIDv4(t *testing.T) {
	id, err := NewDeviceID()
	if err != nil {
		t.Fatalf("NewDeviceID: %v", err)
	}
	if id == (DeviceID{}) {
		t.Fatal("DeviceID is all-zero")
	}
	// Version nibble == 4, variant top bits == 10.
	if id[6]>>4 != 0x4 {
		t.Fatalf("version nibble = %x, want 4", id[6]>>4)
	}
	if id[8]>>6 != 0x2 {
		t.Fatalf("variant bits = %b, want 10", id[8]>>6)
	}
	s := id.String()
	if len(s) != 36 || strings.Count(s, "-") != 4 {
		t.Fatalf("String() = %q, want canonical 8-4-4-4-12 UUID", s)
	}
}

func TestGenerateProducesMatchingBundleAndDevice(t *testing.T) {
	srvPriv, _ := wgengine.GeneratePrivateKey()
	bundle, device, err := Generate(GenerateParams{
		ServerWGPublicKey: srvPriv.PublicKey(),
		ServerEndpoint:    "vpn.example.com:443",
		ServerName:        "vpn.example.com",
		ServerCAPEM:       "-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----\n",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Identity is shared between the two records.
	if bundle.DeviceID != device.DeviceID {
		t.Fatal("bundle/device DeviceID mismatch")
	}
	if bundle.AuthPSK != device.AuthPSK {
		t.Fatal("bundle/device AuthPSK mismatch")
	}
	// PSK is 32 bytes of hex.
	psk, err := hex.DecodeString(bundle.AuthPSK)
	if err != nil || len(psk) != 32 {
		t.Fatalf("AuthPSK hex = %q (decoded %d bytes), want 32", bundle.AuthPSK, len(psk))
	}
	// The registry's WG public key is the public half of the bundle's private key.
	priv, err := ParseKey(bundle.WGPrivateKey)
	if err != nil {
		t.Fatalf("ParseKey(WGPrivateKey): %v", err)
	}
	if priv.PublicKey().Hex() != device.WGPublicKey {
		t.Fatal("device WGPublicKey is not the public half of the bundle's private key")
	}
	if bundle.ServerWGPublicKey != srvPriv.PublicKey().Hex() {
		t.Fatal("bundle ServerWGPublicKey mismatch")
	}
	if bundle.ServerEndpoint != "vpn.example.com:443" {
		t.Fatal("ServerEndpoint not carried")
	}
}

func TestBundleJSONRoundTrip(t *testing.T) {
	srvPriv, _ := wgengine.GeneratePrivateKey()
	bundle, _, _ := Generate(GenerateParams{
		ServerWGPublicKey: srvPriv.PublicKey(),
		ServerEndpoint:    "host:443",
		ServerName:        "host",
	})
	data, err := bundle.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if got != bundle {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, bundle)
	}
}

func TestGenerateUniqueDevices(t *testing.T) {
	srvPriv, _ := wgengine.GeneratePrivateKey()
	p := GenerateParams{ServerWGPublicKey: srvPriv.PublicKey(), ServerEndpoint: "h:443", ServerName: "h"}
	a, _, _ := Generate(p)
	b, _, _ := Generate(p)
	if a.DeviceID == b.DeviceID || a.AuthPSK == b.AuthPSK || a.WGPrivateKey == b.WGPrivateKey {
		t.Fatal("two generated devices share secret/identity material")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./provision/ -run 'TestNewDeviceID|TestGenerate|TestBundle' -v`
Expected: FAIL — `undefined: NewDeviceID`, `undefined: Generate`, etc. (`ParseKey` is added in Task 2; if the compiler complains it is undefined here, that is expected — but to keep Task 1 self-contained, define `ParseKey` in Task 1's provision.go as specified below so this test compiles.)

- [ ] **Step 3: Write the implementation**

Create `core/provision/provision.go`:
```go
// Package provision mints gvpn device credentials. Generate produces a client
// Bundle (DeviceID, AUTH PSK, WireGuard keypair, server coordinates) and a
// matching server registry Device record (DeviceID, AUTH PSK, WG public key).
// The server loads the registry via FileStore to authenticate devices and
// configure WireGuard peers. Pure Go, no cgo.
package provision

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/g00dvin/gvpn/core/wgengine"
)

// authPSKSize is the size in bytes of the in-tunnel AUTH pre-shared key.
const authPSKSize = 32

// DeviceID is a 16-byte UUIDv4 device identifier.
type DeviceID [16]byte

// NewDeviceID generates a random UUIDv4 DeviceID.
func NewDeviceID() (DeviceID, error) {
	var id DeviceID
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return DeviceID{}, err
	}
	id[6] = (id[6] & 0x0f) | 0x40 // version 4
	id[8] = (id[8] & 0x3f) | 0x80 // variant 10xx
	return id, nil
}

// String returns the canonical 8-4-4-4-12 hyphenated hex UUID.
func (d DeviceID) String() string {
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(d[0:4]), hex.EncodeToString(d[4:6]),
		hex.EncodeToString(d[6:8]), hex.EncodeToString(d[8:10]),
		hex.EncodeToString(d[10:16]))
}

// Bundle is the client-side device bundle: everything a client needs to connect.
// It contains secrets (WGPrivateKey, AuthPSK) and must be stored 0600.
type Bundle struct {
	DeviceID          string `json:"device_id"`            // UUID string
	AuthPSK           string `json:"auth_psk"`             // hex, 32 bytes
	WGPrivateKey      string `json:"wg_private_key"`       // hex, 32 bytes
	ServerWGPublicKey string `json:"server_wg_public_key"` // hex, 32 bytes
	ServerEndpoint    string `json:"server_endpoint"`      // host:port
	ServerName        string `json:"server_name"`          // TLS server name
	ServerCAPEM       string `json:"server_ca_pem,omitempty"` // trust anchor PEM (optional)
}

// Device is the server-side registry record for one device.
type Device struct {
	DeviceID    string `json:"device_id"`     // UUID string
	AuthPSK     string `json:"auth_psk"`      // hex, 32 bytes
	WGPublicKey string `json:"wg_public_key"` // hex, 32 bytes
}

// GenerateParams holds the server-side coordinates embedded into a new bundle.
type GenerateParams struct {
	ServerWGPublicKey wgengine.Key
	ServerEndpoint    string
	ServerName        string
	ServerCAPEM       string
}

// Generate mints a new device: a UUIDv4 DeviceID, a random AUTH PSK, and a
// WireGuard keypair. It returns the client Bundle and the server Device record,
// which share the DeviceID and AUTH PSK; the Device carries the WG public key
// whose private half lives only in the Bundle.
func Generate(p GenerateParams) (Bundle, Device, error) {
	id, err := NewDeviceID()
	if err != nil {
		return Bundle{}, Device{}, err
	}
	psk := make([]byte, authPSKSize)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		return Bundle{}, Device{}, err
	}
	wgPriv, err := wgengine.GeneratePrivateKey()
	if err != nil {
		return Bundle{}, Device{}, err
	}
	pskHex := hex.EncodeToString(psk)
	idStr := id.String()

	bundle := Bundle{
		DeviceID:          idStr,
		AuthPSK:           pskHex,
		WGPrivateKey:      wgPriv.Hex(),
		ServerWGPublicKey: p.ServerWGPublicKey.Hex(),
		ServerEndpoint:    p.ServerEndpoint,
		ServerName:        p.ServerName,
		ServerCAPEM:       p.ServerCAPEM,
	}
	device := Device{
		DeviceID:    idStr,
		AuthPSK:     pskHex,
		WGPublicKey: wgPriv.PublicKey().Hex(),
	}
	return bundle, device, nil
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

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./provision/ -run 'TestNewDeviceID|TestGenerate|TestBundle' -v`
Expected: PASS. Also `/home/goodvin/.local/go/bin/go vet ./provision/` — clean.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/provision/provision.go core/provision/provision_test.go core/go.mod core/go.sum
git commit -m "feat(provision): device IDs, bundle, and Generate

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Registry + FileStore

**Files:** Create `core/provision/registry.go`, `core/provision/registry_test.go`.

- [ ] **Step 1: Write the failing test**

Create `core/provision/registry_test.go`:
```go
package provision

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/wgengine"
)

// compile-time: FileStore satisfies authgate.DeviceStore.
var _ authgate.DeviceStore = (*FileStore)(nil)

func newDevice(t *testing.T) (Bundle, Device) {
	t.Helper()
	srv, _ := wgengine.GeneratePrivateKey()
	b, d, err := Generate(GenerateParams{ServerWGPublicKey: srv.PublicKey(), ServerEndpoint: "h:443", ServerName: "h"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return b, d
}

func TestLoadRegistryMissingFileIsEmpty(t *testing.T) {
	devs, err := LoadRegistry(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("LoadRegistry(missing): %v", err)
	}
	if len(devs) != 0 {
		t.Fatalf("missing registry returned %d devices, want 0", len(devs))
	}
}

func TestAppendAndLoad(t *testing.T) {
	reg := filepath.Join(t.TempDir(), "devices.json")
	_, d1 := newDevice(t)
	_, d2 := newDevice(t)
	if err := AppendDevice(reg, d1); err != nil {
		t.Fatalf("append 1: %v", err)
	}
	if err := AppendDevice(reg, d2); err != nil {
		t.Fatalf("append 2: %v", err)
	}
	devs, err := LoadRegistry(reg)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(devs) != 2 {
		t.Fatalf("loaded %d devices, want 2", len(devs))
	}
}

func TestAppendRejectsDuplicate(t *testing.T) {
	reg := filepath.Join(t.TempDir(), "devices.json")
	_, d := newDevice(t)
	if err := AppendDevice(reg, d); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := AppendDevice(reg, d); err == nil {
		t.Fatal("appending a duplicate DeviceID: want error, got nil")
	}
}

func TestFileStoreLookups(t *testing.T) {
	reg := filepath.Join(t.TempDir(), "devices.json")
	b, d := newDevice(t)
	if err := AppendDevice(reg, d); err != nil {
		t.Fatalf("append: %v", err)
	}
	store, err := NewFileStore(reg)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	id, err := ParseDeviceID(d.DeviceID)
	if err != nil {
		t.Fatalf("ParseDeviceID: %v", err)
	}
	psk, ok := store.Lookup(id)
	if !ok {
		t.Fatal("Lookup: device not found")
	}
	if hex.EncodeToString(psk) != b.AuthPSK {
		t.Fatal("Lookup PSK mismatch with bundle")
	}
	wgPub, ok := store.WGPublicKey(id)
	if !ok {
		t.Fatal("WGPublicKey: device not found")
	}
	priv, _ := ParseKey(b.WGPrivateKey)
	if wgPub != priv.PublicKey() {
		t.Fatal("WGPublicKey is not the public half of the bundle's private key")
	}
	if _, ok := store.Lookup([16]byte{0xFF}); ok {
		t.Fatal("Lookup unknown device returned ok")
	}
}

func TestParseDeviceIDRoundTrip(t *testing.T) {
	id, _ := NewDeviceID()
	parsed, err := ParseDeviceID(id.String())
	if err != nil {
		t.Fatalf("ParseDeviceID: %v", err)
	}
	if !bytes.Equal(parsed[:], id[:]) {
		t.Fatal("ParseDeviceID round trip mismatch")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./provision/ -run 'TestLoad|TestAppend|TestFileStore|TestParseDeviceID' -v`
Expected: FAIL — `undefined: LoadRegistry`, `undefined: NewFileStore`, `undefined: ParseDeviceID`.

- [ ] **Step 3: Write the implementation**

Create `core/provision/registry.go`:
```go
package provision

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/g00dvin/gvpn/core/wgengine"
)

// LoadRegistry reads the device registry JSON file (a JSON array of Device). A
// missing or empty file yields an empty registry (not an error).
func LoadRegistry(path string) ([]Device, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var devs []Device
	if err := json.Unmarshal(data, &devs); err != nil {
		return nil, fmt.Errorf("provision: parse registry %q: %w", path, err)
	}
	return devs, nil
}

// AppendDevice adds d to the registry file (creating it if absent), rejecting a
// duplicate DeviceID. The file is written 0600 (it contains AUTH PSKs).
func AppendDevice(path string, d Device) error {
	devs, err := LoadRegistry(path)
	if err != nil {
		return err
	}
	for _, e := range devs {
		if e.DeviceID == d.DeviceID {
			return fmt.Errorf("provision: device %s already registered", d.DeviceID)
		}
	}
	devs = append(devs, d)
	data, err := json.MarshalIndent(devs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// FileStore is an in-memory device store loaded from a registry file. It
// implements authgate.DeviceStore (DeviceID -> AUTH PSK) and resolves each
// device's WireGuard public key for the data path.
type FileStore struct {
	psk map[[16]byte][]byte
	wg  map[[16]byte]wgengine.Key
}

// NewFileStore loads the registry at path into a FileStore.
func NewFileStore(path string) (*FileStore, error) {
	devs, err := LoadRegistry(path)
	if err != nil {
		return nil, err
	}
	fs := &FileStore{psk: make(map[[16]byte][]byte), wg: make(map[[16]byte]wgengine.Key)}
	for _, d := range devs {
		id, err := ParseDeviceID(d.DeviceID)
		if err != nil {
			return nil, fmt.Errorf("provision: bad device_id %q: %w", d.DeviceID, err)
		}
		psk, err := hex.DecodeString(d.AuthPSK)
		if err != nil {
			return nil, fmt.Errorf("provision: bad auth_psk for %s: %w", d.DeviceID, err)
		}
		pub, err := ParseKey(d.WGPublicKey)
		if err != nil {
			return nil, fmt.Errorf("provision: bad wg_public_key for %s: %w", d.DeviceID, err)
		}
		fs.psk[id] = psk
		fs.wg[id] = pub
	}
	return fs, nil
}

// Lookup implements authgate.DeviceStore.
func (s *FileStore) Lookup(deviceID [16]byte) ([]byte, bool) {
	psk, ok := s.psk[deviceID]
	return psk, ok
}

// WGPublicKey returns the device's registered WireGuard public key.
func (s *FileStore) WGPublicKey(deviceID [16]byte) (wgengine.Key, bool) {
	k, ok := s.wg[deviceID]
	return k, ok
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

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./provision/ -v`
Expected: PASS (whole package). Also `/home/goodvin/.local/go/bin/go vet ./provision/` — clean.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/provision/registry.go core/provision/registry_test.go
git commit -m "feat(provision): registry file + FileStore (authgate.DeviceStore)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: `gvpn-provision` CLI

**Files:** Create `core/cmd/gvpn-provision/main.go`, `core/cmd/gvpn-provision/main_test.go`.

The CLI logic lives in `run(args []string, out io.Writer) error` for testability; `main` just calls it.

- [ ] **Step 1: Write the failing test**

Create `core/cmd/gvpn-provision/main_test.go`:
```go
package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/wgengine"
)

func TestRunProvisionsBundleAndRegistry(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "devices.json")
	out := filepath.Join(dir, "bundle.json")
	srv, _ := wgengine.GeneratePrivateKey()

	var buf bytes.Buffer
	err := run([]string{
		"--server-wg-pubkey", srv.PublicKey().Hex(),
		"--endpoint", "vpn.example.com:443",
		"--server-name", "vpn.example.com",
		"--registry", reg,
		"--out", out,
	}, &buf)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	// Bundle file parses and carries the server coordinates.
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	b, err := provision.ParseBundle(data)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if b.ServerEndpoint != "vpn.example.com:443" || b.ServerName != "vpn.example.com" {
		t.Fatalf("bundle server coords wrong: %+v", b)
	}

	// Registry loads as a store; PSK matches the bundle; WG pubkey matches the priv.
	store, err := provision.NewFileStore(reg)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	id, _ := provision.ParseDeviceID(b.DeviceID)
	psk, ok := store.Lookup(id)
	if !ok || hex.EncodeToString(psk) != b.AuthPSK {
		t.Fatal("registry PSK does not match bundle")
	}
	priv, _ := provision.ParseKey(b.WGPrivateKey)
	if wgPub, ok := store.WGPublicKey(id); !ok || wgPub != priv.PublicKey() {
		t.Fatal("registry WG pubkey does not match bundle private key")
	}

	// Output mentions the DeviceID but never the secrets.
	o := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte(b.DeviceID)) {
		t.Fatal("output should mention the DeviceID")
	}
	if bytes.Contains(buf.Bytes(), []byte(b.AuthPSK)) || bytes.Contains(buf.Bytes(), []byte(b.WGPrivateKey)) {
		t.Fatalf("output leaked secret material: %q", o)
	}
}

func TestRunRequiresServerFlags(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"--endpoint", "h:443"}, &buf); err == nil {
		t.Fatal("run without --server-wg-pubkey/--server-name: want error, got nil")
	}
}

func TestRunSecondProvisionAppends(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "devices.json")
	srv, _ := wgengine.GeneratePrivateKey()
	args := func(out string) []string {
		return []string{
			"--server-wg-pubkey", srv.PublicKey().Hex(),
			"--endpoint", "h:443", "--server-name", "h",
			"--registry", reg, "--out", out,
		}
	}
	var buf bytes.Buffer
	if err := run(args(filepath.Join(dir, "a.json")), &buf); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if err := run(args(filepath.Join(dir, "b.json")), &buf); err != nil {
		t.Fatalf("run 2: %v", err)
	}
	devs, _ := provision.LoadRegistry(reg)
	if len(devs) != 2 {
		t.Fatalf("registry has %d devices after two provisions, want 2", len(devs))
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./cmd/gvpn-provision/ -v`
Expected: FAIL — `undefined: run`.

- [ ] **Step 3: Write the implementation**

Create `core/cmd/gvpn-provision/main.go`:
```go
// Command gvpn-provision mints a gvpn device: it writes a client bundle and
// appends the device to the server registry.
//
// Example:
//
//	gvpn-provision --server-wg-pubkey <hex> --endpoint vpn.example.com:443 \
//	    --server-name vpn.example.com --ca server-ca.pem \
//	    --registry /etc/gvpn/devices.json --out alice.json
package main

import (
	"flag"
	"fmt"
	"io"
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
	fs := flag.NewFlagSet("gvpn-provision", flag.ContinueOnError)
	fs.SetOutput(out)
	serverPub := fs.String("server-wg-pubkey", "", "server WireGuard public key, hex (required)")
	endpoint := fs.String("endpoint", "", "server endpoint host:port (required)")
	serverName := fs.String("server-name", "", "server TLS name (required)")
	caPath := fs.String("ca", "", "path to the server CA certificate PEM (optional)")
	registry := fs.String("registry", "devices.json", "server device registry file to append to")
	outPath := fs.String("out", "", "client bundle output file (default: <device-id>.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serverPub == "" || *endpoint == "" || *serverName == "" {
		return fmt.Errorf("--server-wg-pubkey, --endpoint and --server-name are required")
	}

	pub, err := provision.ParseKey(*serverPub)
	if err != nil {
		return fmt.Errorf("invalid --server-wg-pubkey: %w", err)
	}
	var caPEM string
	if *caPath != "" {
		raw, err := os.ReadFile(*caPath)
		if err != nil {
			return fmt.Errorf("read --ca: %w", err)
		}
		caPEM = string(raw)
	}

	bundle, device, err := provision.Generate(provision.GenerateParams{
		ServerWGPublicKey: pub,
		ServerEndpoint:    *endpoint,
		ServerName:        *serverName,
		ServerCAPEM:       caPEM,
	})
	if err != nil {
		return err
	}
	if err := provision.AppendDevice(*registry, device); err != nil {
		return err
	}

	dst := *outPath
	if dst == "" {
		dst = device.DeviceID + ".json"
	}
	data, err := bundle.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}

	fmt.Fprintf(out, "provisioned device %s\n  bundle:   %s\n  registry: %s\n", device.DeviceID, dst, *registry)
	return nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test -race ./cmd/gvpn-provision/ -v`
Expected: PASS. Also build the binary: `/home/goodvin/.local/go/bin/go build ./cmd/gvpn-provision` and `/home/goodvin/.local/go/bin/go vet ./cmd/...`.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/cmd/gvpn-provision/main.go core/cmd/gvpn-provision/main_test.go
git commit -m "feat(provision): gvpn-provision CLI

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Final review + PR

**Files:** none (verification + PR only).

- [ ] **Step 1: Whole-repo verification**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test -race ./provision/ ./cmd/...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test -race ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go build ./...
```
Expected: all PASS / clean.

- [ ] **Step 2: Opus final code + security review** (controller dispatches a fresh Opus subagent)

Security checklist: (1) AUTH PSK and WG private key from `crypto/rand` (full sizes); (2) bundle and registry files written `0o600`; (3) the CLI never prints PSK/private-key material (only DeviceID + paths); (4) `FileStore` satisfies `authgate.DeviceStore` and `Lookup`/`WGPublicKey` resolve correctly; (5) duplicate DeviceID is rejected on append; (6) DeviceID is a valid UUIDv4; (7) hex parsing rejects wrong-length keys.

- [ ] **Step 3: Push and open PR** (trivial / `gh` — Haiku)

```bash
cd /home/goodvin/git/gvpn
git push -u origin feat/provisioning
gh pr create --base main --head feat/provisioning \
  --title "Device provisioning + registry + gvpn-provision CLI" \
  --body "Implements design §6: device enrollment. gvpn-provision mints a device (UUIDv4 DeviceID, AUTH PSK, WireGuard keypair), writes a client bundle, and appends a record to the server device registry.

- core/provision/provision.go: DeviceID (UUIDv4), Bundle (client) + Device (server) + Generate + bundle JSON.
- core/provision/registry.go: LoadRegistry/AppendDevice (0600, dup-rejecting) + FileStore implementing authgate.DeviceStore (DeviceID->PSK) and WGPublicKey (DeviceID->WG pubkey) for the data path.
- core/cmd/gvpn-provision: the CLI (testable run()).

Pure Go, tested with -race (generate/bundle JSON, registry append+load, FileStore lookups, CLI end to end). Reuses core/wgengine key helpers. Files holding secrets are 0600; the CLI prints only the DeviceID and paths.

This unblocks the server assembly (next plan), which loads the registry via FileStore to authenticate devices and configure WireGuard peers.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

---

## Self-Review

**Spec coverage (design §6):** `gvpn-provision` CLI emitting a device bundle + registering the peer → Tasks 1–3. Bundle = WG keypair + AUTH PSK + server endpoint + trust anchor (CA PEM) + DeviceID → Task 1 (`Bundle`). Server registers DeviceID + WG pubkey + token(PSK) → Task 2 (`Device`, `AppendDevice`, `FileStore`). The server consuming this (authenticate via `authgate.DeviceStore`, configure WG peer via `WGPublicKey`) → `FileStore` satisfies the interface; the wiring itself is the next (server) plan.

**Placeholder scan:** none — full code in every step. (Task 1 defines `ParseKey` so its test compiles before Task 2 adds `ParseDeviceID`.)

**Type consistency:** `DeviceID [16]byte` + `NewDeviceID()` + `String()`; `Bundle{DeviceID,AuthPSK,WGPrivateKey,ServerWGPublicKey,ServerEndpoint,ServerName,ServerCAPEM}` (+`Marshal`/`ParseBundle`); `Device{DeviceID,AuthPSK,WGPublicKey}`; `GenerateParams{ServerWGPublicKey wgengine.Key,...}` + `Generate(...)(Bundle,Device,error)`; `ParseKey(string)(wgengine.Key,error)` (Task 1, used in Tasks 2/3); `LoadRegistry`/`AppendDevice`/`NewFileStore`/`(*FileStore).Lookup`/`WGPublicKey`/`ParseDeviceID` (Task 2); `run([]string, io.Writer) error` (Task 3). `FileStore.Lookup` matches `authgate.DeviceStore.Lookup([16]byte)([]byte,bool)` exactly.
