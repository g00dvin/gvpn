# Android GOST Tunnel e2e Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove real IP traffic flows through the WireGuard tunnel over a real GOST transport on the Android ABI, via one portable test run on the Linux `core` job and the x86_64 emulator.

**Architecture:** A new `TestGOSTTunnelHTTP` in `core/goste2e` reuses the full pipeline from `core/server/e2e_test.go` (provision → `server.Server` → WireGuard over the transport → HTTP through the tunnel) but swaps the transport from plain TCP to a real loopback `gosttls` connection (`gosttls.Listen` ⟵ `gosttls.Dial`), with a CLI-free GOST cert. The same package binary runs on Linux (apt engine) and cross-compiles for the emulator.

**Tech Stack:** Go 1.24 + cgo, OpenSSL 3 + gost engine, wireguard-go + netstack, Android NDK 26 / API 21, `reactivecircus/android-emulator-runner`, GitHub Actions.

**Execution model:** CI is the only Android verifier. Task 1 is fully verifiable on Linux (apt engine). Task 2 is CI-iterated. Execute **inline**.

**Branch:** `feat/android-gost-tunnel` (already created, spec already committed there).

---

## File Structure

- **Create** `core/goste2e/tunnel_test.go` — `gostNetListener` adapter + `TestGOSTTunnelHTTP`. (Task 1)
- **Modify** `.github/workflows/build.yml` — run the tunnel test on the same emulator boot (no new build step). (Task 2)
- **Modify** `client/android/README.md` — note the on-device tunnel-over-GOST check. (Task 3)

---

## Task 1: `core/goste2e` tunnel-over-GOST test

**Files:**
- Create: `core/goste2e/tunnel_test.go`
- Reference (pattern to mirror, transport swapped to gosttls): `core/server/e2e_test.go`

Verifiable locally on Linux with the apt gost engine.

- [ ] **Step 1: Write the test**

Create `core/goste2e/tunnel_test.go`:

```go
package goste2e

import (
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/gosttls"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/server"
	"github.com/g00dvin/gvpn/core/session"
	"github.com/g00dvin/gvpn/core/transport"
	"github.com/g00dvin/gvpn/core/wgengine"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// gostNetListener adapts *gosttls.Listener (whose Accept returns *gosttls.Conn,
// itself a net.Conn) to the net.Listener that server.Serve consumes.
type gostNetListener struct{ *gosttls.Listener }

func (l gostNetListener) Accept() (net.Conn, error) { return l.Listener.Accept() }

// TestGOSTTunnelHTTP drives the entire gvpn pipeline over a real loopback
// GOST-TLS transport and pushes real IP traffic through the WireGuard tunnel:
// provision -> server.Server(gosttls listener) <- gosttls.Dial client ->
// AUTH -> SESSION_BIND -> WireGuard -> HTTP GET through the tunnel. Run on the
// emulator it proves IP traffic flows over GOST on the Android ABI.
//
// With GVPN_REQUIRE_GOST=1 a missing engine is fatal (not skipped).
func TestGOSTTunnelHTTP(t *testing.T) {
	if err := gosttls.Init(); err != nil {
		if os.Getenv("GVPN_REQUIRE_GOST") == "1" {
			t.Fatalf("gost engine required but unavailable: %v", err)
		}
		t.Skipf("gost engine unavailable: %v", err)
	}

	// CLI-free GOST cert: the server presents it, the client pins it as CA.
	dir := t.TempDir()
	cert := filepath.Join(dir, "e2e.crt")
	key := filepath.Join(dir, "e2e.key")
	if err := gosttls.GenerateSelfSignedGOSTCert("e2e.gvpn", cert, key, 1); err != nil {
		t.Fatalf("GenerateSelfSignedGOSTCert: %v", err)
	}

	serverWG, _ := wgengine.GeneratePrivateKey()
	serverTunIP := netip.MustParseAddr("10.100.0.1")
	clientTunIP := netip.MustParseAddr("10.100.0.2")

	reg := filepath.Join(dir, "registry.json")
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

	serverTun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverTunIP}, nil, 1420)
	if err != nil {
		t.Fatalf("server CreateNetTUN: %v", err)
	}
	srv, err := server.New(
		authgate.NewGate(store, nil),
		session.NewManager(time.Minute),
		store,
		server.Config{WGPrivateKey: serverWG, LogLevel: device.LogLevelSilent},
		serverTun,
	)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	gln, err := gosttls.Listen("tcp", "127.0.0.1:0", gosttls.Config{CertFile: cert, KeyFile: key})
	if err != nil {
		t.Fatalf("gosttls.Listen: %v", err)
	}
	ln := gostNetListener{gln}
	defer ln.Close()
	go srv.Serve(ln)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := gosttls.Dial(ctx, "tcp", ln.Addr().String(),
		gosttls.Config{CAFile: cert, ServerName: "e2e.gvpn"})
	if err != nil {
		t.Fatalf("gosttls.Dial: %v", err)
	}
	defer conn.Close()

	psk, _ := hex.DecodeString(bundle.AuthPSK)
	devID, _ := provision.ParseDeviceID(bundle.DeviceID)
	if err := authgate.WriteAuth(conn, psk, devID); err != nil {
		t.Fatalf("WriteAuth: %v", err)
	}
	var zsid [16]byte
	var ztok [32]byte
	if _, _, err := session.ClientBind(conn, zsid, ztok); err != nil {
		t.Fatalf("ClientBind: %v", err)
	}

	clientPriv, _ := provision.ParseKey(bundle.WGPrivateKey)
	clientTun, clientNet, err := netstack.CreateNetTUN([]netip.Addr{clientTunIP}, nil, 1420)
	if err != nil {
		t.Fatalf("client CreateNetTUN: %v", err)
	}
	clientEng, err := wgengine.New(clientTun, transport.NewStreamTransport(conn), wgengine.Config{
		PrivateKey:    clientPriv,
		PeerPublicKey: serverWG.PublicKey(),
		AllowedIPs:    []string{"0.0.0.0/0"},
		Endpoint:      "server:0",
		Keepalive:     5,
	}, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("client wgengine: %v", err)
	}
	defer clientEng.Close()

	httpLn, err := serverNet.ListenTCP(&net.TCPAddr{IP: serverTunIP.AsSlice(), Port: 80})
	if err != nil {
		t.Fatalf("netstack ListenTCP: %v", err)
	}
	httpSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello through gost tunnel")
	})}
	go httpSrv.Serve(httpLn)
	defer httpSrv.Close()

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
	if string(body) != "hello through gost tunnel" {
		t.Fatalf("tunnel HTTP body = %q, want the greeting (pipeline/handshake over GOST failed)", body)
	}
}
```

- [ ] **Step 2: Verify it runs (not skipped) on Linux with the engine**

Run: `cd core && CGO_ENABLED=1 GVPN_REQUIRE_GOST=1 /home/goodvin/.local/go/bin/go test ./goste2e/ -run TestGOSTTunnelHTTP -v`
Expected: `--- PASS: TestGOSTTunnelHTTP` (RUN then PASS, not SKIP).

- [ ] **Step 3: Verify the whole package is race-clean**

Run: `cd core && CGO_ENABLED=1 GVPN_REQUIRE_GOST=1 /home/goodvin/.local/go/bin/go test -race ./goste2e/`
Expected: `ok  github.com/g00dvin/gvpn/core/goste2e` (both the handshake and tunnel tests pass under `-race`).

- [ ] **Step 4: Commit**

```bash
git add core/goste2e/tunnel_test.go
git commit -m "goste2e: WireGuard-over-GOST tunnel e2e (HTTP through the tunnel)"
```

---

## Task 2: CI — run the tunnel test on the emulator

**Files:**
- Modify: `.github/workflows/build.yml`

No new build step — `goste2e.test` already contains the new test. Add one run+grep to the emulator job's `script:`.

- [ ] **Step 1: Add the tunnel run to the emulator step**

In `.github/workflows/build.yml`, in the `android-engine-smoke` job's "Run self-test on emulator" step `script:`, after the existing `TestGOSTControlHandshake` grep line, append:

```yaml
            adb shell "cd /data/local/tmp && TMPDIR=/data/local/tmp GVPN_REQUIRE_GOST=1 ./goste2e.test -test.run TestGOSTTunnelHTTP -test.v" | tee /tmp/tunnel.txt
            grep -q '^--- PASS: TestGOSTTunnelHTTP' /tmp/tunnel.txt
```

(The `goste2e.test` binary is already built and pushed in the existing steps; the
tunnel test is in the same package, so it is already inside that binary.)

- [ ] **Step 2: Validate YAML, push, open PR, iterate to green**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/build.yml'))" && echo "YAML OK"
git add .github/workflows/build.yml
git commit -m "ci: run WireGuard-over-GOST tunnel e2e on the emulator"
git push -u origin feat/android-gost-tunnel
gh pr create --title "Android GOST tunnel e2e (WireGuard-over-GOST on emulator)" --body "<summary>"
gh run list --branch feat/android-gost-tunnel --limit 1
gh run watch <run-id> --exit-status
gh run view <run-id> --log-failed
```
Iterate until the emulator job and all required checks are green. The new test
pulls `server`/`wgengine`/`netstack` into the cross-compiled `goste2e.test`; the
likely (low) friction is that cross-compile linking, surfaced at the "Build
handshake e2e binary" step — fix per `--log-failed`.

---

## Task 3: Docs + finalize

**Files:**
- Modify: `client/android/README.md`

- [ ] **Step 1: Note the on-device tunnel check**

In `client/android/README.md`, extend the emulator job's bullet (the
`core/goste2e` line) to add that the job now also runs `TestGOSTTunnelHTTP`:
real IP traffic (an HTTP GET) flows through the WireGuard tunnel over a real
GOST transport on-device. Note that reconnect/roaming over GOST and device→host
networking remain later sub-projects.

- [ ] **Step 2: Confirm CI still green and commit**

```bash
git add client/android/README.md
git commit -m "docs(android): note on-device WireGuard-over-GOST tunnel e2e"
git push
```
Confirm the README push keeps the emulator job (and other required checks) green.
The PR is mergeable once all checks are green.

---

## Self-Review

**Spec coverage:**
- Full pipeline over real GOST transport, loopback, HTTP through the tunnel (spec Architecture/Components) → Task 1 test.
- `gostNetListener` adapter for `gosttls.Listener` → `server.Serve` (spec Components) → Task 1 adapter.
- CLI-free cert, client pins via `CAFile`, never disable verification (spec Error handling) → Task 1 cert + Dial config.
- Env-gate `GVPN_REQUIRE_GOST=1` (spec Error handling) → Task 1 Init gate.
- Portable test: Linux `core` job + emulator, no new build step (spec CI) → Task 1 Steps 2–3 (Linux) + Task 2 (emulator; `goste2e.test` already built).
- Out of scope (reconnect/roaming, device→host) → not present.
- Docs → Task 3.

**Placeholder scan:** the PR `--body "<summary>"` in Task 2 is a CLI argument filled at run time, not plan content. No `TODO`/"add error handling"/uncoded test steps.

**Type consistency:** mirrors `core/server/e2e_test.go` exactly for `provision.{NewCipherFromHex,NewFileStore,AddUser,Generate,GenerateParams,AddDevice,Device,ParseDeviceID,ParseKey}`, `server.{New,Config{WGPrivateKey,LogLevel}}`, `wgengine.{GeneratePrivateKey,New,Config{PrivateKey,PeerPublicKey,AllowedIPs,Endpoint,Keepalive}}`, `transport.NewStreamTransport`, `authgate.{NewGate,WriteAuth}`, `session.{NewManager,ClientBind}`, `netstack.CreateNetTUN`, `device.LogLevelSilent`. The only deltas vs that file: `gosttls.{Init,GenerateSelfSignedGOSTCert,Listen,Dial,Config}` + the `gostNetListener` adapter (mirrors `cmd/gvpn-server/listener.go`). `bundle.{AuthPSK,DeviceID,WGPrivateKey}` and `mat.{DeviceID,User,WGPublic,TunnelIP,AuthPSK}` match the reference test.
