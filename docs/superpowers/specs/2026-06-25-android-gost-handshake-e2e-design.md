# Android GOST Handshake + Control e2e (on emulator) — Design

**Status:** approved for planning (2026-06-25)
**Sub-project:** Client phase, SP4 — prove a real GOST-TLS handshake (and the gvpn
control protocol) on the Android ABI.
**Predecessors:** SP1 `core/mobile` (PR #15), SP2 Android `.aar` (PR #16), SP3
Android GOST engine runtime (PR #17).

## Problem

SP3 proved the gost engine *loads* on Android and does in-process GOST crypto
(keygen + self-sign + verify), but it never performed a **handshake**: no GOST-TLS
session was negotiated over a socket, and none of the gvpn framed control
protocol (AUTH gate, SESSION_BIND) was exercised on the Android ABI.

The existing server e2e tests (`core/server/e2e_test.go`,
`core/server/enroll_e2e_test.go`) inject a plain-TCP listener + netstack TUN —
they deliberately do **not** use the real GOST engine. So no test anywhere proves
a real GOST-TLS handshake through the client pipeline, on any platform. This
sub-project closes that gap on the Android ABI.

## Locked decision (scope)

**Handshake + control, loopback.** On the emulator, in one process:

- a **real GOST-TLS handshake** — `gosttls.Listen` ⟵ `gosttls.Dial`, both via the
  static engine;
- plus the gvpn **AUTH gate** (`authgate`) and **SESSION_BIND** (`session`)
  control exchange over the encrypted connection.

Cert is minted CLI-free via `gosttls.GenerateSelfSignedGOSTCert` (no `openssl`
CLI, which is absent on the emulator). **No host networking** (no device→host
server, no `10.0.2.2`) — keeps CI flakiness low.

**Explicitly out of scope (deferred):** device→host networked server; full
WireGuard tunnel/IP-traffic over GOST on the emulator; the Kotlin `VpnService`
app; iOS; mobile `Enroll`.

## Architecture

A new test-only package `core/goste2e` holds one integration test that runs the
gvpn client↔server control handshake over a real loopback GOST-TLS connection:

```
server goroutine:  gosttls.Listen(127.0.0.1:0)
                     -> Accept
                     -> authgate.Gate.Handle(conn)        // HMAC auth token
                     -> session.Manager.Bind(deviceID, conn)  // SESSION_BIND
client:            gosttls.Dial(addr)
                     -> authgate.WriteAuth(conn, psk, deviceID)
                     -> session.ClientBind(conn, sid, token)
```

`authgate` and `session` operate on `net.Conn` and do **not** import `gosttls`
(verified: no import cycle), so the new package can import all three. The test is
**portable** (no `android` build tag): the same source runs on the Linux `core`
job (apt gost engine) for fast feedback and, cross-compiled for `android/amd64`,
on the emulator. Both endpoints use the engine — static on Android, apt on Linux.

## Components

### `core/goste2e/handshake_test.go` (new)

- **`mintGOSTCert(t) (certPath, keyPath string)`** — `gosttls.GenerateSelfSignedGOSTCert("e2e.gvpn", cert, key, 1)` into `t.TempDir()`. CLI-free; the SP3 self-test already proved this path works on-device.
- **Configs** — server `gosttls.Config{CertFile, KeyFile}`; client `gosttls.Config{CAFile: certPath, ServerName: "e2e.gvpn"}`. The client **pins** the self-signed GOST cert as its CA; verification is never disabled.
- **Identity** — a 32-byte PSK + 16-byte deviceID registered in an `authgate` device store; a `session.Manager` on the server side.
- **`TestGOSTControlHandshake`** —
  1. env-gate: `Init()`; if it fails and `GVPN_REQUIRE_GOST=1`, `t.Fatal`, else `t.Skip` (same pattern as SP3's self-test, so CI/emulator cannot false-green);
  2. `gosttls.Listen` on `127.0.0.1:0`;
  3. server goroutine: `Accept` → `Gate.Handle` → `Manager.Bind`;
  4. client: `Dial` → `WriteAuth` → `ClientBind`;
  5. assert: negotiated cipher contains `"GOST"` (`gosttls.CipherName`); `Gate.Handle` returns `Kind == Device` with the expected `DeviceID`; `ClientBind` returns a non-zero session id; the server goroutine reported no error.

## Data flow / what it proves

The GOST-TLS handshake completes over a real socket (the engine negotiates a GOST
ciphersuite — asserted, not assumed), then the gvpn control bytes (HMAC auth
token, then SESSION_BIND) round-trip through the encrypted `net.Conn`. On the
emulator this proves transport **and** control-plane work on the Android ABI —
the rung above SP3's in-process keygen.

## CI

Extend the existing emulator job (`android-engine-smoke`, renamed to reflect both
checks, e.g. *"Android GOST on-device (engine + handshake)"*):

- after the existing `gosttls` self-test, also `go test -c` the `goste2e` package
  for `android/amd64` (NDK x86_64 clang, OpenSSL + gost engine via
  `PKG_CONFIG_PATH`), `adb push` it, and run it on the **same** emulator boot with
  `TMPDIR=/data/local/tmp GVPN_REQUIRE_GOST=1`, grepping its output for
  `^--- PASS: TestGOSTControlHandshake`.
- one new emulator binary, **no new emulator boot**.

The Linux `core` job already runs `go test ./...`, which picks up the new
`core/goste2e` package automatically (apt engine) — free fast-feedback coverage.

## Error handling

- Constraints unchanged: certificate verification always on (client pins the
  GOST cert via `CAFile`); no private keys / PSKs / session keys logged.
- `GVPN_REQUIRE_GOST=1` turns an engine-absent skip into a hard failure on
  CI/emulator, preventing false-greens.

## Testing

- **Linux `core` job:** `TestGOSTControlHandshake` runs with the apt engine (fast
  feedback; also runs under `-race` like the rest of the module).
- **Android x86_64 emulator:** the cross-compiled `goste2e` binary runs on-device
  and is the SP4 acceptance gate, alongside the SP3 self-test.

## Execution model

CI is the only Android verifier (no local NDK/emulator). The new test is locally
verifiable on Linux with the apt engine; the emulator run is CI-only. Execute
**inline** (push → `gh run watch` → fix → repeat), as in SP2/SP3.
