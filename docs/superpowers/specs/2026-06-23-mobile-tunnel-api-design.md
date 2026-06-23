# gvpn — Shared Mobile Tunnel API (Design)

**Status:** approved 2026-06-23. First sub-project of the client phase.
**Scope:** a single, pure-Go package `core/mobile` that wraps the merged transport/WireGuard core into a small, gomobile-bindable API. Both the Android and iOS clients bind this package; their UIs come in later sub-projects. This document is the source of truth for that package.

## 1. Context & goals

The server side of the MVP is complete (plans 1–14): `gvpn-server` terminates GOST TLS on `:443`, runs the AUTH gate + decoy, multiplexes WireGuard over one kernel TUN with NAT, supports dynamic in-band enrollment, and ships an admin console + enrollment share page. What remains for the MVP is the **clients**.

All three clients (Windows/Wails, Android, iOS) share the same Go transport+WireGuard core, which is **cgo-only at `gosttls`** and otherwise pure Go. The mobile clients link the core through **gomobile** (`.aar` for Android, `.xcframework` for iOS). The risk is the **gomobile boundary**: gomobile only binds a restricted set of Go types, and the host must hand the Go layer a TUN file descriptor. We de-risk that boundary **once**, in a shared package, before building any platform UI.

**Goal:** a package `core/mobile` exposing a minimal, gomobile-bindable API that brings up and tears down a gvpn tunnel for an already-enrolled device, with transparent reconnection across network changes, reporting status to the host. It is verifiable end-to-end in pure Go (no device, no gomobile toolchain) against the real `server.Server`.

**Non-goals (this sub-project):** platform UI; `gomobile bind` cross-compilation into `.aar`/`.xcframework` (a platform-build concern, see §7); dynamic enrollment from a share link/QR (`Enroll`, deferred — see §6); persisting credentials in the Go layer (the host owns storage, §2).

## 2. Ownership & statefulness

The Go layer is **stateless**. The host (Android Keystore-backed app, iOS Keychain-backed app) owns secure storage of the device credentials. `Connect` is given the device bundle as JSON on every call; the Go layer never writes secrets to disk. This is idiomatic for mobile and keeps the Go core free of platform key-management.

A *device bundle* is the existing `provision.Bundle`: `{device_id, auth_psk (hex), wg_private_key (hex), tunnel_ip, server_wg_public_key (hex), server_endpoint, server_name, server_ca_pem}`. It is produced today by `gvpn-provision device add` (admin pre-provision) or, in the future, by a completed `Enroll`. It carries the **full server CA PEM**, so `Connect` verifies the GOST server by CA-pinning with existing `gosttls`.

## 3. Exported API surface (gomobile-bindable)

gomobile binds only: signed/unsigned integers, `float`, `bool`, `string`, `[]byte`, `error`, and *bound* types (struct pointers, interfaces); functions may return at most one non-error value plus `error`; no other slices, maps, or channels cross the boundary. The surface respects this exactly:

```go
package mobile

// StatusReporter is implemented by the host; gomobile binds it as a callback
// class (Kotlin/Swift). All strings are human-readable and contain no secrets.
type StatusReporter interface {
    OnState(state string)   // see the state set below
    OnError(message string) // a non-fatal or fatal error description
}

// Tunnel is an opaque, bound handle to one running tunnel. Create one per
// Android VpnService / iOS NEPacketTunnelProvider instance.
type Tunnel struct { /* unexported fields */ }

// Connect brings up a tunnel for an already-enrolled device described by
// bundleJSON (a provision.Bundle), running WireGuard over the host-provided TUN
// file descriptor tunFD, and reports lifecycle changes to reporter. It returns a
// Tunnel handle once the engine is started; the data path runs in the
// background. The caller owns tunFD until Disconnect.
func Connect(bundleJSON string, tunFD int, reporter StatusReporter) (*Tunnel, error)

// Disconnect tears the tunnel down (engine, transport, TUN) exactly once.
func (t *Tunnel) Disconnect() error
```

**State set** (`OnState` argument): `"connecting"`, `"connected"`, `"reconnecting"`, `"disconnected"`. v1 reliably emits `connecting` → `connected` (after the engine is up) → `disconnected`; `reconnecting` is best-effort (most reconnects are hidden inside `ReconnectingTransport`). `OnError` carries dial/handshake/config failures.

## 4. Internal composition

`Connect` composes only existing, exported core APIs:

1. **Parse** `bundleJSON` → `provision.Bundle`; derive the device id (`provision.ParseDeviceID`), the AUTH PSK (hex-decode `auth_psk`), the WG private key and the server WG public key (`provision.ParseKey`).
2. **Handshake dialer** — a `transport.Dialer` that, on each (re)connect, performs the *entire* client handshake and returns a connection positioned at the WireGuard data path:
   - `gosttls.Dial(ctx, "tcp", server_endpoint, gosttls.Config{CAPEM: server_ca_pem, ServerName: server_name})` (GOST TLS, server cert verified against the bundle's in-memory CA — see the helper note below);
   - `authgate.WriteAuth(conn, authPSK, deviceID)` (the in-tunnel AUTH frame);
   - `session.ClientBind(conn, [16]byte{}, [32]byte{})` (a fresh zero-bind per connect; `ClientBind` already accepts a zero sid/token and runs the request/response, leaving the conn at the data path. The server creates a new session each time; WireGuard's own crypto session + endpoint roaming carry tunnel continuity, so no resume token needs to be threaded).
   Encapsulating auth+bind *inside* the dialer is what makes reconnection transparent: `ReconnectingTransport` re-invokes it on every network change, with no session-token bookkeeping. `ReconnectingConfig.SessionToken` is left empty (the dialer owns the bind).
3. **Reconnecting transport** — `transport.NewReconnectingTransport(ReconnectingConfig{Dialer: handshakeDialer})`. This is the `PacketTransport` WireGuard reads/writes; it hides connection loss (paced backoff) so a Wi-Fi↔LTE switch is observed by WireGuard as a brief stall, never an EOF.
4. **TUN from the host fd** — `os.NewFile(uintptr(tunFD), "gvpn-tun")` → `tun.CreateTUNFromFile(file, mtu)` (the standard gomobile WireGuard pattern; the host's VpnService/utun fd backs the device).
5. **Engine** — `wgengine.New(tunDev, reconnectingTransport, wgengine.Config{PrivateKey: bundleWGPriv, PeerPublicKey: serverWGPub, AllowedIPs: ["0.0.0.0/0"], Endpoint: "gvpn-server:0", Keepalive: 25}, logLevel)`. (`Endpoint` is a non-empty placeholder that arms this side as the WireGuard initiator; the `Bind` ignores its value, as in the existing client tunnel tests.)
6. **Report** `connected` once the engine is up; keep handles for `Disconnect`.

`Disconnect` closes the engine (which closes the bind + transport) then the TUN, guarded by a `sync.Once`, and reports `disconnected`.

**Required small core helper — in-memory CA in `gosttls`:** the device bundle carries the server CA as a PEM string, but `gosttls.Config` today only accepts a CA *file* path (`CAFile`). Writing the PEM to a temp file on a phone is awkward and unnecessary, so this sub-project adds an additive `gosttls.Config.CAPEM` (an in-memory CA PEM; when set, the client context loads it into the verify store via an OpenSSL memory BIO instead of `SSL_CTX_load_verify_locations`). This is the only core change outside the `mobile` package; it is small, additive (existing `CAFile` behavior unchanged), cgo-confined to `gosttls`, and does not change wire behavior. `session.ClientBind` already accepts a zero sid/token, so no `session` change is needed.

## 5. Testing

The package is verified **without** a device or the gomobile toolchain:

- **Unit:** bundle parsing/validation; error paths (bad JSON, bad keys); `Disconnect` idempotency; `StatusReporter` receives the expected state sequence (via a recording reporter).
- **End-to-end (pure Go):** stand up the real `server.Server` over a netstack TUN + plain-TCP listener (the pattern used by `core/server` and `cmd/gvpn-server` tests), provision a device into its store, then call `mobile.Connect` with a netstack **client** TUN fd and tunnel HTTP through it — proving the full GOST-less-in-test composition (the test injects a plain-TCP dialer; production injects GOST). Run under `-race`.
- **gomobile-bindability:** guaranteed by the §3 type discipline. A real `gomobile bind` (cgo cross-compile of OpenSSL+gost for arm64-android/-ios) is **not** run here; it belongs to the platform-client plans (§7).

For testability, the dialer (and the listener it dials) is **injectable**: `Connect` uses the production GOST dialer; tests pass a plain-TCP dialer to the same internal constructor. The exported `Connect` keeps the simple production signature; a small internal `connect(deps)` seam carries the injected dialer (mirroring how `cmd/gvpn-server`'s `run`/`serveDeps` is tested).

## 6. Deferred: `Enroll` (next sub-project)

Dynamic enrollment from a `gvpn://enroll` share link (the phone-onboarding path) is deferred to the immediate next plan because it needs a server-cert-verification decision the current code does not cover: the QR/deep-link carries a **cert fingerprint** (`caf`), not a CA PEM, but `gosttls` today verifies against a CA. The next plan will add a `gosttls` **fingerprint-pinning** dial mode and wire `enroll.Exchange` into a `mobile.Enroll(enrollURI, tunFD, reporter) (*Tunnel, error)` whose `Tunnel.Bundle() string` returns the granted device bundle JSON for the host to persist. v1 leaves a clean seam: the same internal tunnel construction is reused, with enrollment as a one-shot creds-acquisition step before the steady device-path tunnel.

## 7. Build note (platform-build concern, not this sub-project)

Binding `core/mobile` for real devices requires `gomobile bind` to cross-compile the cgo `gosttls` package — i.e. OpenSSL 3 + the gost engine — for each target ABI (arm64/x86_64 Android, arm64 iOS). That toolchain/cross-build is owned by the Android and iOS client sub-projects, not this one. This sub-project delivers and proves the **Go API** in pure Go; it deliberately does not attempt the cross-compiled artifact.

## 8. Components & boundaries (summary)

| Unit | Responsibility | Depends on |
|---|---|---|
| `mobile.Connect`/`Tunnel` | gomobile-bindable lifecycle; compose the stack from a bundle + TUN fd | provision, gosttls, authgate, session, transport, wgengine, tun |
| handshake `Dialer` | full client handshake (GOST → AUTH → SESSION_BIND) per (re)connect | gosttls, authgate, session, frame |
| `StatusReporter` (host-implemented) | receive state/error callbacks | — |

The mobile package is the only new code; it is a thin composition layer over already-tested units, so its own surface stays small and focused.
