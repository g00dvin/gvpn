# Android GOST Tunnel e2e (WireGuard-over-GOST on emulator) — Design

**Status:** approved for planning (2026-06-26)
**Sub-project:** Client phase, SP5 — prove real IP traffic flows through the
WireGuard tunnel over a real GOST transport, on the Android ABI.
**Predecessors:** SP1 `core/mobile` (#15), SP2 `.aar` (#16), SP3 engine runtime
(#17), SP4 handshake + control e2e (#18).

## Problem

The on-device Android proof ladder so far: SP2 *builds* the `.aar`, SP3 the engine
*loads* and does GOST crypto, SP4 a real GOST-TLS *handshake* + the gvpn AUTH /
SESSION_BIND control protocol complete on the emulator. The top rung is still
missing: **no test pushes real IP traffic through the WireGuard tunnel over a real
GOST transport** on Android.

The existing full-tunnel test, `core/server/e2e_test.go`
(`TestServerEndToEndTunnelHTTP`), already drives the entire pipeline —
provision → auth → SESSION_BIND → WireGuard over the transport → HTTP through the
tunnel (asserting the response body). But its transport is plain `net.Listen` /
`net.Dial`, not GOST. The mobile e2e (`core/mobile/mobile_e2e_test.go`) likewise
uses a plain-TCP dialer. So WireGuard-over-real-GOST is unproven on any platform.
This sub-project closes that on the Android ABI.

## Locked decision (scope)

**Happy-path tunnel, loopback-in-emulator.** In one emulator process: provision a
device, bring up the full pipeline over a **real** `gosttls` transport
(`server.Server` + a `gosttls` listener ⟵ `gosttls.Dial` client), and pass real
IP traffic — an HTTP GET through the WireGuard tunnel returns the expected body.

**Out of scope (deferred):** reconnect / roaming over GOST (a second
dial + SESSION_BIND resume); device→host networking; the Kotlin `VpnService` app;
iOS; mobile `Enroll`.

## Architecture

A new test `TestGOSTTunnelHTTP` in `core/goste2e` (alongside the SP4 handshake
test) runs the entire gvpn pipeline in one process, the transport being a real
loopback GOST-TLS connection:

```
provision device (FileStore: AddUser, Generate, AddDevice)
server:  server.Server(serverTun = netstack) <- Serve( gostNetListener( gosttls.Listen ) )
client:  gosttls.Dial -> authgate.WriteAuth -> session.ClientBind
         -> wgengine.New(clientTun = netstack, transport.NewStreamTransport(gostConn))
server runs HTTP on 10.100.0.1:80 (server netstack)
client HTTP GET http://10.100.0.1/ via client netstack  ==> asserts the greeting body
```

Everything except the transport is identical to `core/server/e2e_test.go`: the
same `provision` → `server.New` → WireGuard-over-mux → netstack TUNs →
HTTP-through-tunnel. The only swaps are `net.Listen`→`gosttls.Listen` and
`net.Dial`→`gosttls.Dial`, plus a CLI-free GOST cert. The package binary already
runs on Linux CI (apt engine) and cross-compiles for the emulator (SP4).

## Components

### `core/goste2e/tunnel_test.go` (new)

- **`gostNetListener struct{ *gosttls.Listener }`** with `Accept() (net.Conn, error)` —
  mirrors the unexported helper in `cmd/gvpn-server/listener.go`. Needed because
  `gosttls.Listener.Accept` returns `*gosttls.Conn`, not `net.Conn`, so it does
  not directly satisfy the `net.Listener` that `server.Serve` consumes.
- **`TestGOSTTunnelHTTP`**:
  1. env-gate: `gosttls.Init()`; under `GVPN_REQUIRE_GOST=1` a failure is fatal, else skip (same pattern as SP3/SP4);
  2. mint a GOST cert: `gosttls.GenerateSelfSignedGOSTCert("e2e.gvpn", cert, key, 1)` into `t.TempDir()`;
  3. provision: `provision.NewCipherFromHex`, `NewFileStore`, `AddUser`, `Generate(user, clientTunIP, GenerateParams{ServerWGPublicKey, ServerEndpoint, ServerName})`, `AddDevice`;
  4. server: `netstack.CreateNetTUN([serverTunIP])`, `server.New(authgate.NewGate(store,nil), session.NewManager(time.Minute), store, server.Config{WGPrivateKey, LogLevel: device.LogLevelSilent}, serverTun)`; `gosttls.Listen("tcp","127.0.0.1:0", Config{CertFile,KeyFile})` wrapped in `gostNetListener`; `go srv.Serve(adapter)`;
  5. client: `gosttls.Dial(ctx,"tcp",ln.Addr(), Config{CAFile: cert, ServerName: "e2e.gvpn"})` → `authgate.WriteAuth` → `session.ClientBind(zero,zero)` → `wgengine.New(clientTun, transport.NewStreamTransport(conn), wgengine.Config{PrivateKey, PeerPublicKey: serverWGpub, AllowedIPs: ["0.0.0.0/0"], Endpoint: "server:0", Keepalive: 5}, Silent)`;
  6. server HTTP greeting on `serverNet.ListenTCP(serverTunIP:80)`; client `http.Client{Transport: {DialContext: clientNet.DialContext}}` GETs `http://10.100.0.1/` in a retry loop with a deadline;
  7. assert the body equals the greeting (a non-match means the pipeline/handshake failed).

The GOST `ServerName` (`"e2e.gvpn"`, matching the cert CN/SAN) is independent of
`provision`'s stored `ServerEndpoint`/`ServerName` fields, which this test does
not dial through.

## Data flow / what it proves

The WireGuard handshake and the IP packets ride inside the real GOST-TLS stream.
An HTTP request/response completing through the tunnel means
encrypt → frame → GOST-TLS → TCP and back all work together on the Android ABI —
the build → load → handshake → **tunnel** top rung.

## CI

No new build step: `goste2e.test` already compiles the whole `core/goste2e`
package, so the new test ships in the existing binary. In the emulator job's
`script:`, after the handshake check, add one invocation:

```
adb shell "cd /data/local/tmp && TMPDIR=/data/local/tmp GVPN_REQUIRE_GOST=1 ./goste2e.test -test.run TestGOSTTunnelHTTP -test.v" | tee /tmp/tunnel.txt
grep -q '^--- PASS: TestGOSTTunnelHTTP' /tmp/tunnel.txt
```

The Linux `core` job runs the new test automatically via `go test ./...`. The one
thing only CI confirms is that pulling `server` / `wgengine` / `netstack` into the
cross-compiled `goste2e.test` still links for `android/amd64` — all pure-Go on top
of the already-cgo `gosttls`, so low risk.

## Error handling / testing

- Constraints unchanged: certificate verification always on (client pins the GOST
  cert via `CAFile`); no private keys / PSKs / session keys logged.
- `GVPN_REQUIRE_GOST=1` turns an engine-absent skip into a hard failure on
  CI/emulator, preventing false-greens.
- **Linux `core` job:** the test runs with the apt engine, under `-race` like the
  rest of the module (fast feedback).
- **Android x86_64 emulator:** the cross-compiled run is the SP5 acceptance gate,
  alongside the SP3 self-test and SP4 handshake e2e.

## Execution model

CI is the only Android verifier. The test is locally verifiable on Linux with the
apt engine; the emulator run is CI-only. Execute **inline** (push → `gh run watch`
→ fix), as in SP2–SP4.
