# Mobile Tunnel API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Per-task model assignment (standing rule):** **Sonnet** subagent implements each code task; **Opus** (controller) manages tasks and reviews each diff, and dispatches a fresh **Opus** subagent for the final review; **Haiku** subagent does the `gh` push + PR.

**Goal:** Build `core/mobile` — a small, gomobile-bindable, stateless client tunnel API (`Connect`/`Disconnect` + a host `StatusReporter`) that composes the gvpn core (GOST TLS → AUTH → SESSION_BIND → reconnecting transport → WireGuard) over a host-provided TUN file descriptor, plus the one additive core change it needs (an in-memory CA in `gosttls`).

**Architecture:** `core/mobile` is a thin composition layer over already-tested units. Per (re)connect, a handshake `Dialer` does GOST-dial → `authgate.WriteAuth` → `session.ClientBind`, returning a conn at the WireGuard data path; `transport.ReconnectingTransport` re-invokes it on every network change (transparent Wi-Fi↔LTE roaming); WireGuard runs over it on a TUN built from the host fd. The Go layer is stateless (the host owns credential storage). The dialer is injectable so the package is verified in pure Go (plain-TCP dialer + netstack TUN against the real `server.Server`), while production injects the GOST dialer.

**Tech Stack:** Go 1.24, the merged core (`provision`, `gosttls` [cgo], `authgate`, `session`, `transport`, `wgengine`), `golang.zx2c4.com/wireguard/{tun,device,tun/netstack}`. `core/mobile` imports `gosttls`, so it is a cgo package — build/test with `CGO_ENABLED=1`. Toolchain `/home/goodvin/.local/go/bin/go`. Module `github.com/g00dvin/gvpn/core`.

**Design reference:** `docs/superpowers/specs/2026-06-23-mobile-tunnel-api-design.md` §3 (API), §4 (composition), §5 (testing).

---

## Conventions

- Toolchain: `/home/goodvin/.local/go/bin/go`. `mobile` + `gosttls` are cgo: `cd /home/goodvin/git/gvpn/core && CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./gosttls/ ./mobile/`.
- Branch `feat/mobile-api` off `main` (already created; the design spec is committed there).
- Commits end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- `.gitignore` already covers binaries / secrets / `*.pem`. Only `git add` the files each task names.
- **Additive only:** the sole core change outside `mobile` is a new `gosttls.Config.CAPEM` field; existing `CAFile` behavior is unchanged.

## Decisions locked for this plan

- **In-memory CA:** add `gosttls.Config.CAPEM` (a PEM string). When set, the client context loads it into the verify store via an OpenSSL memory BIO; `CAFile` remains the fallback; with neither set, client dial errors.
- **Stateless API:** `Connect(bundleJSON string, tunFD int, reporter StatusReporter) (*Tunnel, error)` + `(*Tunnel).Disconnect() error`. gomobile-bindable types only.
- **Handshake in the dialer:** GOST-dial → `WriteAuth(authPSK, deviceID)` → `ClientBind(zero, zero)`. `ReconnectingConfig.SessionToken` left empty.
- **Injectable dialer:** internal `newTunnel(cc, tunDev, dial, reporter)` takes the dialer; `Connect` injects the GOST dialer, tests inject a plain-TCP dialer (sharing the same `handshake` helper).
- **WG client config:** peer = server WG key, `AllowedIPs ["0.0.0.0/0"]`, `Endpoint "gvpn-server:0"` (non-empty placeholder arming the initiator), `Keepalive 25`, log level silent.
- **`Enroll` is out of scope** (next sub-project; needs `gosttls` fingerprint pinning).

## File structure

```
core/gosttls/config.go            + Config.CAPEM + gvpn_add_ca_pem cgo + newClientCtx branch   (MODIFY)
core/gosttls/capem_test.go         round-trip Dial(CAPEM) against a generated GOST cert         (CREATE)
core/mobile/mobile.go              StatusReporter, Tunnel, parseBundle, gostDialer, handshake,
                                   Connect, newTunnel, Disconnect                               (CREATE)
core/mobile/mobile_test.go         parseBundle + Connect-error + reporter unit tests            (CREATE)
core/mobile/mobile_e2e_test.go     pure-Go tunnel e2e (plain-TCP dialer + netstack)             (CREATE)
```

---

## Task 1: gosttls in-memory CA (`Config.CAPEM`)

**Files:** Modify `core/gosttls/config.go`; create `core/gosttls/capem_test.go`.

- [ ] **Step 1: Write the failing test — create `core/gosttls/capem_test.go`:**

```go
package gosttls

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCAPEMVerifiesGeneratedCert proves an in-memory CA PEM (Config.CAPEM) is an
// accepted alternative to CAFile: it generates a GOST server cert, reads the
// cert PEM, and completes a handshake with the client pinning that PEM.
func TestCAPEMVerifiesGeneratedCert(t *testing.T) {
	if err := Init(); err != nil {
		t.Skipf("gost engine unavailable: %v", err)
	}
	dir := t.TempDir()
	cert := filepath.Join(dir, "gost.crt")
	key := filepath.Join(dir, "gost.key")
	if err := GenerateSelfSignedGOSTCert("localhost", cert, key, 365); err != nil {
		t.Fatalf("GenerateSelfSignedGOSTCert: %v", err)
	}
	caPEM, err := os.ReadFile(cert)
	if err != nil {
		t.Fatalf("read cert pem: %v", err)
	}

	ln, err := Listen("tcp", "127.0.0.1:0", Config{CertFile: cert, KeyFile: key})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	srvErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := c.Read(buf); err != nil {
			srvErr <- err
			return
		}
		_, err = c.Write([]byte("pong"))
		srvErr <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cc, err := Dial(ctx, "tcp", ln.Addr().String(), Config{CAPEM: string(caPEM), ServerName: "localhost"})
	if err != nil {
		t.Fatalf("Dial with CAPEM: %v", err)
	}
	defer cc.Close()
	if _, err := cc.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := cc.Read(got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("got %q, want pong", got)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestClientCtxRequiresSomeCA(t *testing.T) {
	if err := Init(); err != nil {
		t.Skipf("gost engine unavailable: %v", err)
	}
	// Neither CAPEM nor CAFile set -> a client dial must fail at context build,
	// never silently skip verification.
	_, err := Dial(context.Background(), "tcp", "127.0.0.1:1", Config{ServerName: "x"})
	if err == nil {
		t.Fatal("Dial with no CA configured: want error")
	}
}
```

- [ ] **Step 2: Run to confirm FAIL**

Run: `cd /home/goodvin/git/gvpn/core && CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./gosttls/ -run 'TestCAPEM|TestClientCtxRequires' -v 2>&1 | tail -20`
Expected: FAIL — `unknown field CAPEM in struct literal` (and the no-CA test won't yet error at build).

- [ ] **Step 3: Edit `core/gosttls/config.go`**

(3a) Add `CAPEM` to the `Config` struct (after `CAFile`):
```go
	CAFile     string
	CAPEM      string // in-memory CA PEM; an alternative to CAFile (CAFile wins if both set... see newClientCtx)
	ServerName string
```
(Keep the existing `CertFile`/`KeyFile` fields and the rest of the struct as-is.)

(3b) In the cgo preamble at the top of `config.go`, add the x509/pem/bio includes and a helper. The current preamble includes `<openssl/ssl.h>`, `<openssl/err.h>`, `<stdlib.h>` and defines `gvpn_set_min_proto`/`gvpn_set_max_proto`. Add these includes and this function to that same comment block:
```c
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

// gvpn_add_ca_pem loads a single PEM CA certificate from memory into ctx's
// verify store. Returns 1 on success, 0 on failure.
static int gvpn_add_ca_pem(SSL_CTX *ctx, const char *pem) {
    BIO *bio = BIO_new_mem_buf(pem, -1);
    if (bio == NULL) return 0;
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (cert == NULL) return 0;
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    int ok = X509_STORE_add_cert(store, cert);
    X509_free(cert);
    return ok;
}
```

(3c) In `newClientCtx`, replace the CA-loading block — currently:
```go
	cCA := C.CString(cfg.CAFile)
	defer C.free(unsafe.Pointer(cCA))
	if C.SSL_CTX_load_verify_locations(ctx, cCA, nil) != 1 {
		C.SSL_CTX_free(ctx)
		return nil, fmt.Errorf("gosttls: load CA %q: %s", cfg.CAFile, lastError())
	}
	// Require the server to present a certificate that chains to the CA.
	C.SSL_CTX_set_verify(ctx, C.SSL_VERIFY_PEER, nil)
```
with:
```go
	switch {
	case cfg.CAPEM != "":
		cPEM := C.CString(cfg.CAPEM)
		defer C.free(unsafe.Pointer(cPEM))
		if C.gvpn_add_ca_pem(ctx, cPEM) != 1 {
			C.SSL_CTX_free(ctx)
			return nil, fmt.Errorf("gosttls: load in-memory CA: %s", lastError())
		}
	case cfg.CAFile != "":
		cCA := C.CString(cfg.CAFile)
		defer C.free(unsafe.Pointer(cCA))
		if C.SSL_CTX_load_verify_locations(ctx, cCA, nil) != 1 {
			C.SSL_CTX_free(ctx)
			return nil, fmt.Errorf("gosttls: load CA %q: %s", cfg.CAFile, lastError())
		}
	default:
		C.SSL_CTX_free(ctx)
		return nil, fmt.Errorf("gosttls: no CA configured (set Config.CAPEM or Config.CAFile)")
	}
	// Require the server to present a certificate that chains to the CA.
	C.SSL_CTX_set_verify(ctx, C.SSL_VERIFY_PEER, nil)
```

- [ ] **Step 4: Run to confirm PASS**

```bash
cd /home/goodvin/git/gvpn/core
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./gosttls/ -run 'TestCAPEM|TestClientCtxRequires' -v 2>&1 | tail -30
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./gosttls/ 2>&1 | tail -5
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./gosttls/
```
Expected: PASS (the new CAPEM round-trip + the no-CA error), and the whole `gosttls` package still passes (existing CAFile-based tests unaffected); vet clean.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/gosttls/config.go core/gosttls/capem_test.go
git commit -m "feat(gosttls): in-memory CA (Config.CAPEM) for client verification

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: `core/mobile` package — API, parsing, composition

**Files:** Create `core/mobile/mobile.go`, `core/mobile/mobile_test.go`.

- [ ] **Step 1: Write the failing tests — create `core/mobile/mobile_test.go`:**

```go
package mobile

import (
	"strings"
	"sync"
	"testing"

	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/wgengine"
)

// recordingReporter captures the state/error callbacks for assertions.
type recordingReporter struct {
	mu     sync.Mutex
	states []string
	errors []string
}

func (r *recordingReporter) OnState(s string) {
	r.mu.Lock()
	r.states = append(r.states, s)
	r.mu.Unlock()
}
func (r *recordingReporter) OnError(m string) {
	r.mu.Lock()
	r.errors = append(r.errors, m)
	r.mu.Unlock()
}
func (r *recordingReporter) stateList() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.states...)
}
func (r *recordingReporter) errorCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.errors)
}

// testBundleJSON builds a valid device-bundle JSON for the given server WG key.
func testBundleJSON(t *testing.T, serverPub wgengine.Key, tunnelIP string) string {
	t.Helper()
	b, _, err := provision.Generate("u", tunnelIP, provision.GenerateParams{
		ServerWGPublicKey: serverPub, ServerEndpoint: "127.0.0.1:443", ServerName: "vpn",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := b.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(data)
}

func TestParseBundleValid(t *testing.T) {
	srv, _ := wgengine.GeneratePrivateKey()
	cc, err := parseBundle(testBundleJSON(t, srv.PublicKey(), "10.100.0.2"))
	if err != nil {
		t.Fatalf("parseBundle: %v", err)
	}
	if cc.endpoint != "127.0.0.1:443" || cc.serverName != "vpn" || len(cc.authPSK) == 0 {
		t.Fatalf("parsed config = %+v", cc)
	}
	if cc.serverPub != srv.PublicKey() {
		t.Fatal("server pub key mismatch")
	}
}

func TestParseBundleRejectsBadInput(t *testing.T) {
	if _, err := parseBundle("not json"); err == nil {
		t.Fatal("parseBundle(bad json): want error")
	}
	if _, err := parseBundle(`{"device_id":"zz","auth_psk":"00"}`); err == nil {
		t.Fatal("parseBundle(bad device id): want error")
	}
}

func TestConnectReportsConnectingThenErrorsOnBadBundle(t *testing.T) {
	rep := &recordingReporter{}
	if _, err := Connect("not json", -1, rep); err == nil {
		t.Fatal("Connect(bad bundle): want error")
	}
	states := rep.stateList()
	if len(states) == 0 || states[0] != "connecting" {
		t.Fatalf("states = %v, want first = connecting", states)
	}
	if rep.errorCount() == 0 {
		t.Fatal("Connect failure must report an error")
	}
}
```

- [ ] **Step 2: Run to confirm FAIL**

Run: `cd /home/goodvin/git/gvpn/core && CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./mobile/ -run 'TestParseBundle|TestConnect' -v 2>&1 | tail -20`
Expected: build error — `undefined: parseBundle`/`Connect`/etc. (the package does not exist yet).

- [ ] **Step 3: Create `core/mobile/mobile.go`:**

```go
// Package mobile is the gomobile-bindable client tunnel API: it composes the
// gvpn transport + WireGuard core into Connect/Disconnect over a host-provided
// TUN file descriptor, for the Android and iOS clients. The Go layer is stateless
// (the host owns credential storage). cgo lives underneath in gosttls; the
// exported surface uses only gomobile-bindable types.
package mobile

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/gosttls"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/session"
	"github.com/g00dvin/gvpn/core/transport"
	"github.com/g00dvin/gvpn/core/wgengine"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// tunMTU is the WireGuard tunnel MTU.
const tunMTU = 1420

// StatusReporter is implemented by the host to receive tunnel lifecycle events.
// gomobile binds it as a callback class (Kotlin/Swift). Messages contain no
// secrets.
type StatusReporter interface {
	OnState(state string)   // "connecting","connected","reconnecting","disconnected"
	OnError(message string) // human-readable failure description
}

// Tunnel is an opaque, bound handle to one running tunnel.
type Tunnel struct {
	eng       *wgengine.Engine
	reporter  StatusReporter
	closeOnce sync.Once
}

// clientConfig is a parsed, validated device bundle ready to build a tunnel.
type clientConfig struct {
	deviceID   [16]byte
	authPSK    []byte
	wgPriv     wgengine.Key
	serverPub  wgengine.Key
	endpoint   string
	serverName string
	caPEM      string
}

// parseBundle parses and validates a provision.Bundle JSON into a clientConfig.
func parseBundle(bundleJSON string) (clientConfig, error) {
	b, err := provision.ParseBundle([]byte(bundleJSON))
	if err != nil {
		return clientConfig{}, err
	}
	id, err := provision.ParseDeviceID(b.DeviceID)
	if err != nil {
		return clientConfig{}, fmt.Errorf("mobile: device_id: %w", err)
	}
	psk, err := hex.DecodeString(b.AuthPSK)
	if err != nil {
		return clientConfig{}, fmt.Errorf("mobile: auth_psk: %w", err)
	}
	priv, err := provision.ParseKey(b.WGPrivateKey)
	if err != nil {
		return clientConfig{}, fmt.Errorf("mobile: wg_private_key: %w", err)
	}
	pub, err := provision.ParseKey(b.ServerWGPublicKey)
	if err != nil {
		return clientConfig{}, fmt.Errorf("mobile: server_wg_public_key: %w", err)
	}
	if b.ServerEndpoint == "" {
		return clientConfig{}, fmt.Errorf("mobile: server_endpoint is empty")
	}
	return clientConfig{
		deviceID: id, authPSK: psk, wgPriv: priv, serverPub: pub,
		endpoint: b.ServerEndpoint, serverName: b.ServerName, caPEM: b.ServerCAPEM,
	}, nil
}

// handshake writes the in-tunnel AUTH frame and runs the SESSION_BIND exchange
// (a fresh zero-bind) on conn, leaving it positioned at the WireGuard data path.
// It is shared by the production GOST dialer and the plain-TCP test dialer.
func handshake(conn net.Conn, cc clientConfig) error {
	if err := authgate.WriteAuth(conn, cc.authPSK, cc.deviceID); err != nil {
		return err
	}
	var zsid [16]byte
	var ztok [32]byte
	if _, _, err := session.ClientBind(conn, zsid, ztok); err != nil {
		return err
	}
	return nil
}

// gostDialer is the production handshake dialer: GOST TLS -> AUTH -> SESSION_BIND.
func gostDialer(cc clientConfig) transport.Dialer {
	return func(ctx context.Context) (io.ReadWriteCloser, error) {
		conn, err := gosttls.Dial(ctx, "tcp", cc.endpoint, gosttls.Config{
			CAPEM: cc.caPEM, ServerName: cc.serverName,
		})
		if err != nil {
			return nil, err
		}
		if err := handshake(conn, cc); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

// Connect brings up a tunnel for an already-enrolled device described by
// bundleJSON, running WireGuard over the host TUN file descriptor tunFD, and
// reports lifecycle changes to reporter. The data path runs in the background.
func Connect(bundleJSON string, tunFD int, reporter StatusReporter) (*Tunnel, error) {
	reporter.OnState("connecting")
	cc, err := parseBundle(bundleJSON)
	if err != nil {
		reporter.OnError(err.Error())
		return nil, err
	}
	tunFile := os.NewFile(uintptr(tunFD), "gvpn-tun")
	if tunFile == nil {
		err := fmt.Errorf("mobile: invalid tun fd %d", tunFD)
		reporter.OnError(err.Error())
		return nil, err
	}
	tunDev, err := tun.CreateTUNFromFile(tunFile, tunMTU)
	if err != nil {
		reporter.OnError(err.Error())
		return nil, err
	}
	t, err := newTunnel(cc, tunDev, gostDialer(cc), reporter)
	if err != nil {
		tunDev.Close()
		reporter.OnError(err.Error())
		return nil, err
	}
	return t, nil
}

// newTunnel wires a reconnecting transport + WireGuard engine over tunDev, using
// dial as the (re)connect handshake. dial is injectable so tests drive it over
// plain TCP. On success it reports "connected" and returns a live Tunnel.
func newTunnel(cc clientConfig, tunDev tun.Device, dial transport.Dialer, reporter StatusReporter) (*Tunnel, error) {
	rt := transport.NewReconnectingTransport(transport.ReconnectingConfig{Dialer: dial})
	eng, err := wgengine.New(tunDev, rt, wgengine.Config{
		PrivateKey:    cc.wgPriv,
		PeerPublicKey: cc.serverPub,
		AllowedIPs:    []string{"0.0.0.0/0"},
		Endpoint:      "gvpn-server:0",
		Keepalive:     25,
	}, device.LogLevelSilent)
	if err != nil {
		return nil, err
	}
	reporter.OnState("connected")
	return &Tunnel{eng: eng, reporter: reporter}, nil
}

// Disconnect tears the tunnel down (engine -> bind -> transport -> TUN) exactly
// once and reports "disconnected".
func (t *Tunnel) Disconnect() error {
	var err error
	t.closeOnce.Do(func() {
		err = t.eng.Close()
		t.reporter.OnState("disconnected")
	})
	return err
}
```

- [ ] **Step 4: Run to confirm PASS**

```bash
cd /home/goodvin/git/gvpn/core
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./mobile/ -run 'TestParseBundle|TestConnect' -v
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./mobile/
```
Expected: PASS / clean. (`TestConnectReportsConnectingThenErrorsOnBadBundle` fails parsing before touching the fd, so the invalid fd is never used.)

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/mobile/mobile.go core/mobile/mobile_test.go
git commit -m "feat(mobile): gomobile-bindable Connect/Disconnect tunnel API

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: pure-Go tunnel end-to-end

**Files:** Create `core/mobile/mobile_e2e_test.go`.

This proves the full composition: a real `server.Server` (plain-TCP listener + netstack server TUN) with a provisioned device, driven by `newTunnel` over a plain-TCP handshake dialer and a netstack client TUN, tunneling HTTP — then a clean `Disconnect`. It mirrors the `core/server` e2e but enters through the `mobile` package.

- [ ] **Step 1: Write the test — create `core/mobile/mobile_e2e_test.go`:**

```go
package mobile

import (
	"context"
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
	"github.com/g00dvin/gvpn/core/server"
	"github.com/g00dvin/gvpn/core/session"
	"github.com/g00dvin/gvpn/core/wgengine"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestMobileTunnelEndToEnd(t *testing.T) {
	serverWG, _ := wgengine.GeneratePrivateKey()
	serverTunIP := netip.MustParseAddr("10.100.0.1")
	clientTunIP := netip.MustParseAddr("10.100.0.2")

	// Registry with one provisioned device.
	reg := filepath.Join(t.TempDir(), "registry.json")
	cph, _ := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	store, err := provision.NewFileStore(reg, cph)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if _, _, err := store.AddUser("e2e"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	bundle, mat, err := provision.Generate("e2e", clientTunIP.String(), provision.GenerateParams{
		ServerWGPublicKey: serverWG.PublicKey(), ServerEndpoint: "127.0.0.1:443", ServerName: "vpn",
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

	// Real server over a plain-TCP listener + netstack server TUN.
	serverTun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverTunIP}, nil, 1420)
	if err != nil {
		t.Fatalf("server CreateNetTUN: %v", err)
	}
	srv, err := server.New(authgate.NewGate(store, nil), session.NewManager(time.Minute), store,
		server.Config{WGPrivateKey: serverWG, LogLevel: device.LogLevelSilent}, serverTun)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	// HTTP service on the server's tunnel IP.
	httpLn, err := serverNet.ListenTCP(&net.TCPAddr{IP: serverTunIP.AsSlice(), Port: 80})
	if err != nil {
		t.Fatalf("netstack ListenTCP: %v", err)
	}
	httpSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello from the mobile tunnel")
	})}
	go httpSrv.Serve(httpLn)
	defer httpSrv.Close()

	// Client: parse the bundle, build a plain-TCP handshake dialer + netstack TUN,
	// and bring up the tunnel through the mobile package's newTunnel seam.
	data, _ := bundle.Marshal()
	cc, err := parseBundle(string(data))
	if err != nil {
		t.Fatalf("parseBundle: %v", err)
	}
	plainDial := func(ctx context.Context) (io.ReadWriteCloser, error) {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return nil, err
		}
		if err := handshake(conn, cc); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
	clientTun, clientNet, err := netstack.CreateNetTUN([]netip.Addr{clientTunIP}, nil, 1420)
	if err != nil {
		t.Fatalf("client CreateNetTUN: %v", err)
	}
	rep := &recordingReporter{}
	tunnel, err := newTunnel(cc, clientTun, plainDial, rep)
	if err != nil {
		t.Fatalf("newTunnel: %v", err)
	}

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
	if string(body) != "hello from the mobile tunnel" {
		t.Fatalf("tunnel HTTP body = %q, want the greeting", body)
	}

	// The reporter saw the connect, and Disconnect is clean + idempotent.
	if states := rep.stateList(); len(states) == 0 || states[len(states)-1] != "connected" {
		t.Fatalf("reporter states = %v, want last = connected", states)
	}
	if err := tunnel.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if err := tunnel.Disconnect(); err != nil {
		t.Fatalf("second Disconnect: %v", err)
	}
	if states := rep.stateList(); states[len(states)-1] != "disconnected" {
		t.Fatalf("after Disconnect states = %v, want last = disconnected", states)
	}
}
```

- [ ] **Step 2: Run the e2e**

Run: `cd /home/goodvin/git/gvpn/core && CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./mobile/ -run TestMobileTunnelEndToEnd -v 2>&1 | tail -30`
Expected: PASS — HTTP tunnels through the mobile-built WireGuard tunnel; the reporter ends at `connected`; double `Disconnect` is clean. (A real WireGuard handshake runs; allow a few seconds.)

- [ ] **Step 3: Full package under the race detector**

Run: `cd /home/goodvin/git/gvpn/core && CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test -race ./mobile/ 2>&1 | tail -10`
Expected: PASS (unit tests + e2e), no data races, no goroutine-leak hangs.

- [ ] **Step 4: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/mobile/mobile_e2e_test.go
git commit -m "test(mobile): pure-Go tunnel e2e (plain-TCP dialer + netstack)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Final review + PR

**Files:** none (verification + PR only).

- [ ] **Step 1: Whole-module verification (cgo on)**

```bash
cd /home/goodvin/git/gvpn/core
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test -race ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go build ./...
```
Expected: all PASS / clean.

- [ ] **Step 2: Confirm the gomobile-bindable surface + cgo boundary**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go doc ./mobile/ | sed -n '1,40p'`
Expected: the exported surface is exactly `StatusReporter` (interface, two `string` methods), `Tunnel` (struct), `Connect(string, int, StatusReporter) (*Tunnel, error)`, `(*Tunnel).Disconnect() error` — all gomobile-bindable types (no exported slices/maps/multi-value returns). Also confirm `gosttls` change stayed additive: `/home/goodvin/.local/go/bin/go list -deps ./mobile/ | grep -i gosttls` shows `mobile` depends on gosttls (cgo, expected).

- [ ] **Step 3: Opus final code + security review** (controller dispatches a fresh Opus subagent)

Review focus: the exported `mobile` surface is gomobile-bindable (only int/string/[]byte/error/bound types; single non-error return); cert verification is never disabled — `Connect` passes the bundle's CA via `gosttls.Config.CAPEM`, and `gosttls` errors when neither CAPEM nor CAFile is set (no silent skip); the new `gvpn_add_ca_pem` cgo has no leak (BIO freed, X509 freed on both paths); the handshake dialer composition (GOST → AUTH → SESSION_BIND) is correct and re-runnable for reconnection; `Disconnect` is idempotent (`sync.Once`) and closes engine→transport→TUN with no goroutine leak (run `-race`); `Connect`'s error paths close the TUN they created and report an error; no secret logging (AUTH PSK, WG keys, CA — CA is not secret but keys are); status sequence is sane; the e2e proves a real tunnel through the package. Note any verification-disable, cgo leak, race, goroutine leak, or non-bindable export as Critical/Important.

- [ ] **Step 4: Push and open PR** (trivial / `gh` — Haiku)

```bash
cd /home/goodvin/git/gvpn
git push -u origin feat/mobile-api
gh pr create --base main --head feat/mobile-api \
  --title "Shared mobile tunnel API (core/mobile) + gosttls in-memory CA" \
  --body "The shared, gomobile-bindable client tunnel API that the Android and iOS clients will bind — built and verified in pure Go before any platform UI.

- gosttls: + Config.CAPEM (in-memory CA PEM) so a client can verify the server from the bundle's CA without a temp file; existing CAFile behavior unchanged; client dial errors if neither is set (verification never skipped). cgo-confined.
- core/mobile (stateless, host owns storage): Connect(bundleJSON, tunFD, reporter) (*Tunnel, error) + (*Tunnel).Disconnect(); StatusReporter callback. Per (re)connect a handshake dialer does GOST-dial -> WriteAuth -> ClientBind, wrapped in ReconnectingTransport (transparent Wi-Fi<->LTE roaming), over a host-fd TUN (CreateTUNFromFile), driving wgengine. Exported surface uses only gomobile-bindable types.
- Tested in pure Go: parse/error units + a tunnel e2e that stands up the real server.Server (plain-TCP listener + netstack) and tunnels HTTP through the mobile package via an injected plain-TCP dialer. Under -race.

Out of scope (next sub-project): Enroll (needs gosttls fingerprint pinning for QR links); the actual gomobile bind/cross-compile of cgo OpenSSL for arm64 (owned by the Android/iOS client plans). cmd/gvpn-server unaffected; whole module green under -race + cgo.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

---

## Self-Review

**Spec coverage (design §3–§5):** stateless gomobile-bindable `Connect`/`Disconnect` + `StatusReporter` (Task 2); handshake-in-the-dialer composition over `ReconnectingTransport` + host-fd TUN + `wgengine` (Task 2); the required additive `gosttls.Config.CAPEM` (Task 1); pure-Go unit + tunnel e2e with an injected plain-TCP dialer (Tasks 2–3). `Enroll` and the real gomobile cross-build are explicitly out of scope (design §6, §7) and not in any task. The injectable-dialer seam (design §5) is `newTunnel(cc, tunDev, dial, reporter)`.

**Placeholder scan:** none — every step has complete code or an exact edit (`config.go` struct field, preamble helper, and the `newClientCtx` CA block replacement). The e2e and unit tests are full; the `recordingReporter` is defined in Task 2's test file and reused by Task 3 (same package).

**Type consistency:** `StatusReporter{OnState(string),OnError(string)}`; `Tunnel{eng *wgengine.Engine, reporter, closeOnce}`; `clientConfig{deviceID [16]byte, authPSK []byte, wgPriv/serverPub wgengine.Key, endpoint/serverName/caPEM string}`; `parseBundle(string)(clientConfig,error)`; `handshake(net.Conn, clientConfig) error`; `gostDialer(clientConfig) transport.Dialer`; `Connect(string,int,StatusReporter)(*Tunnel,error)`; `newTunnel(clientConfig, tun.Device, transport.Dialer, StatusReporter)(*Tunnel,error)`; `(*Tunnel).Disconnect() error`; `gosttls.Config.CAPEM string`. Consumes the verified `provision.{ParseBundle,ParseDeviceID,ParseKey,Generate,Bundle.Marshal}`, `authgate.WriteAuth`, `session.ClientBind(conn,[16]byte,[32]byte)`, `transport.{NewReconnectingTransport,ReconnectingConfig{Dialer},Dialer}`, `wgengine.{New,Config,Key,GeneratePrivateKey}`, `gosttls.{Dial,Config}`, `tun.CreateTUNFromFile`, `netstack.CreateNetTUN`.
