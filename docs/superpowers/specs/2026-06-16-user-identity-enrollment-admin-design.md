# gvpn — User Identity, Dynamic Enrollment, Multiplexed Server & Admin (Design)

> Status: approved 2026-06-16. Extends `2026-06-13-gvpn-transport-design.md`. This is the
> authoritative design for the next build phase; it is sliced into five implementation plans
> (§15). The transport spine (frame → GOST TLS → TCP/443), the AUTH gate + decoy, sessions,
> wireguard-go over `PacketTransport`, and device provisioning are already built and merged
> (plans 1–8). This phase adds: a user/device identity model, encrypted-at-rest secrets,
> dynamic self-enrollment, a multiplexed (single-device, many-peer) server data path, the
> `gvpn-server` binary, and a localhost admin web UI with a public enrollment share page.

## 1. Context & goals

Today a device is the only identity: `gvpn-provision` mints a per-device bundle and appends a
record `{deviceID, auth_psk, wg_public_key}` to a JSON registry that the server loads read-only.
The server data path (merged plan 8) is **per-client-device** — one wireguard-go device + one TUN
per connected client — an explicit stepping-stone that does not meet the 1000-client / ≤512 MB
budget and does not match the spec's single-subnet config (`wireguard.address: 10.100.0.1/24`).

This phase delivers the production server and a real operator/user story:

- **Users own multiple devices.** One person can run gvpn on phone, laptop, etc.; each is its own
  WireGuard peer with its own credentials, independently revocable.
- **Dynamic self-enrollment.** A user installs a single *user bundle*; a new device enrolls itself
  on first connect (the server mints its per-device credentials at runtime). No per-device bundle
  hand-off.
- **No plaintext secrets at rest** on the server, and **no hand-editing** the registry.
- **Multiplexed data path** — one wireguard-go device, one TUN on the server subnet, many peers —
  the production architecture matching the spec's config and the perf budget.
- **`gvpn-server` binary** that ties GOST TLS + the multiplexed engine + a real kernel TUN +
  routing/NAT together, with certificate generation built in.
- **Simple admin web UI** (localhost-only) to manage users/devices and publish enrollment links.

## 2. Non-goals & constraints (binding)

- **No custom cryptography.** AEAD (AES-256-GCM / ChaCha20-Poly1305) and the password KDF
  (argon2id/bcrypt) come from the Go stdlib / `golang.org/x/crypto`; the AUTH gate keeps its
  existing HMAC-SHA256 token; GOST comes from the OpenSSL GOST provider already wrapped in
  `core/gosttls`. No new protocols or primitives are invented.
- **WireGuard stays standard** (embedded `wireguard-go`; no shelling out to `wg`/`wg-quick`).
- **Certificate validation is never disabled.**
- **Never log** WireGuard private/symmetric keys, PSKs, the master key, session tokens, or packet
  contents. Enrollment/admin events log at INFO with non-secret identifiers only.
- **cgo stays confined to `core/gosttls`.** `core/{server,wgengine,provision}` remain pure Go;
  `tun/netstack` (gVisor) is **test-only**. The kernel TUN and GOST listener are injected by the
  binary.
- **No orchestrator service.** Enrollment is in-band over the existing GOST-TLS/AUTH channel; the
  admin UI is part of the `gvpn-server` process, not a separate microservice.

## 3. Architecture overview

One `gvpn-server` process exposes three network surfaces:

```
:443              GOST TLS        VPN data path: AUTH gate → mux WireGuard;  decoy fallback
<share.listen>    standard TLS    PUBLIC  GET /enroll/<token>  (phone browsers; operator cert in prod)
127.0.0.1:<admin> plain HTTP      ADMIN UI (localhost only; reach via SSH tunnel; admin login)
```

The process **owns the registry at runtime** and is the **single writer**. The web UI and the
`gvpn-provision` CLI are *clients* of an in-process **admin API**; the CLI writes the registry file
directly only as a bootstrap path when the server is not running. This removes the two-writer
hazard created by runtime enrollment writes.

Component layering (server side):

```
TLS Listener (gosttls)          standard-TLS share listener        admin listener (localhost)
        │                                  │                               │
   AUTH gate ── decoy                 enroll share handler            admin API ── web UI
        │                                  │                               │
  enroll │ device                          └───────────────┬──────────────┘
        ▼                                                   ▼
  Session Manager  ───────────────►   Registry (read-write, encrypted PSKs, single writer)
        │                                                   │
        ▼                                                   ▼
  Multiplexed WireGuard engine (one device, one TUN 10.100.0.1/24, many peers)
        │
   kernel TUN + routing/NAT (binary)
```

## 4. Identity model

- **User** — an explicit registry entity (so a user can exist with zero devices, be disabled, and
  carry guardrail state):
  ```
  User {
    Handle        string     // unique login handle, e.g. "alice"
    EnrollPSKEnc  string      // AEAD(masterKey, enrollPSK); the reusable enrollment credential
    DeviceCap     int         // max devices (default 5)
    EnrollOpen    bool        // self-enrollment allowed (default true)
    Disabled      bool
    CreatedAt     time.Time
  }
  ```
- **Device** — belongs to exactly one user; one device = one WireGuard peer:
  ```
  Device {
    DeviceID   string         // UUIDv4
    User       string         // owning user handle
    WGPublic   string         // hex; the peer's WireGuard public key
    TunnelIP   string         // e.g. "10.100.0.5" (a /32 peer allowed_ip)
    AuthPSKEnc string          // AEAD(masterKey, per-device PSK)
    CreatedAt  time.Time
    Source     string          // "admin" | "enroll"
  }
  ```

A stable 16-byte **user id** (representation deferred to §16) backs `kind=ENROLL` tokens (§6).
Everything in a record is public **except** `EnrollPSKEnc` / `AuthPSKEnc`, which are encrypted.
Per-device PSKs give per-device revocation; the user-level enrollPSK only bootstraps new devices.

## 5. Secrets at rest

- **Master key**: 32 bytes, supplied out-of-band via `GVPN_MASTER_KEY` (hex env var) or
  `--master-key-file` / `server.yaml`'s reference to a key file. **Never** stored in `server.yaml`
  itself. Both `gvpn-provision` (to encrypt on write) and `gvpn-server` (to decrypt on load) need
  it.
- **AEAD**: each secret stored as `nonce ‖ ciphertext` (base64), random nonce per encryption,
  using ChaCha20-Poly1305 or AES-256-GCM (`x/crypto` / stdlib). A `provision.Cipher` helper exposes
  `Seal(plain) string` / `Open(enc) ([]byte, error)`.
- **The AUTH gate is unchanged.** `FileStore` is constructed with the master key; `Lookup(deviceID)`
  decrypts `AuthPSKEnc` and returns the plaintext PSK in memory, so `authgate.DeviceStore` keeps its
  current `Lookup(deviceID) (psk []byte, ok bool)` signature. Plaintext PSKs live only in process
  memory, never on disk.
- **`FileStore` becomes read-write**: an `RWMutex`-guarded in-memory model plus atomic persistence
  (write temp file + `rename`). New methods: `AddDevice(Device)`, `RemoveDevice(id)`,
  `AddUser(User)` / `RemoveUser(handle)`, `Device(id) (Device, bool)`, `User(handle) (User, bool)`,
  `DevicesForUser(handle) []Device`. This also dissolves the plan-8 "loaded once at startup"
  limitation (runtime additions are visible immediately).

## 6. AUTH gate extension — token kind

The AUTH token (`authgate/token.go`) gains a 1-byte **kind** discriminator (the header is already
versioned, so this is forward-compatible):

- `kind = DEVICE` — the existing flow: the 16-byte id is a `DeviceID`; the gate looks up the
  device PSK and verifies; success → VPN data path.
- `kind = ENROLL` — the 16-byte id identifies a **user** (a 16-byte user id derived from the
  handle, e.g. a stored per-user uuid); the gate looks up the user's `enrollPSK` and verifies;
  success → enrollment handler (§7).
- Anything that fails to verify under either path → **decoy** (probe-resistance preserved; the
  decoy never sees a distinguishing error).

`DeviceStore` grows a sibling lookup for users, e.g. `EnrollLookup(userID [16]byte) (psk []byte,
ok bool)`; `authgate.Result` grows `Kind` and `UserID` so the server can branch.

## 7. Dynamic enrollment

Additive on top of per-device credentials — enrollment only *bootstraps* a device; steady-state
traffic uses per-device creds.

**Register a user (admin):** `gvpn-provision user add alice` (or the admin UI) mints a random
`enrollPSK`, stores it encrypted, and emits the **user bundle** (§8).

**First connect from a new device:**
```
device:  generate a fresh WG keypair locally
         GOST-TLS connect → AUTH frame { kind=ENROLL, userID, HMAC(enrollPSK, …) }
server:  verify enroll token → user; reject if Disabled, !EnrollOpen, or len(devices)≥DeviceCap
device:  ENROLL frame { wgPublic }          (a CONTROL/typed frame, after the gate, before DATA)
server:  allocate TunnelIP (§ IPAM) + new DeviceID; generate a per-device PSK
         AddDevice(record)  [persist, encrypted]  +  MuxEngine.AddPeer(wgPublic, TunnelIP/32)  [live]
         reply { deviceID, tunnelIP, devicePSK }   (over the encrypted channel)
device:  persist {deviceID, tunnelIP, devicePSK}; bring up its tunnel; proceed as a normal client
```

**Steady state:** subsequent connects send `kind=DEVICE` with the per-device PSK; the WG handshake
authenticates the peer by key as usual.

**Guardrails:** per-user `DeviceCap` (default 5), per-user `EnrollOpen` toggle (default true),
`device revoke` (drops the record and removes the live peer). Enrollment events are logged at INFO
with `{user, deviceID, tunnelIP}` — no secrets.

**IPAM:** `provision.AllocateIP(existing []Device, subnet netip.Prefix) (netip.Addr, error)` returns
the lowest free host in `subnet` (default `10.100.0.0/24`), reserving `.1` for the server TUN.
Allocation runs both in the CLI (admin pre-provision) and in the server (enrollment), always against
the current registry under the single-writer lock.

## 8. Enrollment bundle & sharing

- **Canonical URI** (one encoder, three renderings):
  ```
  gvpn://enroll?u=<handle>&psk=<base64url enrollPSK>&h=<host:443>&sni=<serverName>[&caf=<sha256-fp>]
  ```
  `caf` (a base64 cert fingerprint to pin) is used when the server uses a self-signed/private GOST
  cert; with a publicly-trusted GOST cert it can be omitted. A full CA PEM is only ever carried in
  the **file** form.
- **Renderings emitted by `gvpn-provision user add` / the admin UI:**
  - **File** `.gvpn` — the URI (or full JSON incl. CA PEM).
  - **Deep link** — the `gvpn://enroll?…` string (copy/paste; the mobile app registers the scheme).
  - **QR** — PNG plus optional terminal ASCII (needs a small Go QR library; keep the payload small,
    i.e. `caf`, not a full PEM).
- **No PIN/passphrase encryption** of the bundle (decided): protection is secure delivery + the
  per-user guardrails. The reusable enrollPSK has no expiry.
- **Public share page** (admin convenience): the admin UI can mint a **share token** — a server-side,
  **TTL'd and revocable** handle (NOT the raw enrollPSK in the URL). `GET /enroll/<token>` on the
  standard-TLS listener renders the QR + `gvpn://` deep link for phone onboarding. An expired or
  revoked token onboards no one, and the user's `DeviceCap` / `EnrollOpen` still gate the actual
  enrollment.

## 9. Multiplexed server data path

One `device.Device`, one TUN (`10.100.0.1/24`), many peers.

- **`muxEndpoint{ id uint64 }`** implements `conn.Endpoint`; the id identifies the *connection* a
  packet arrived on.
- **`wgengine.MuxBind`** (sibling of the merged single-conn `Bind`): `Register(id, pt)` starts a
  per-connection reader goroutine that reads frames and fans them into one shared `recv` channel as
  `(packet, muxEndpoint{id})`; `Deregister(id)` stops that reader. `Open` returns a receive func
  draining the shared channel (concurrency comes from the per-conn readers). `Send(bufs, ep)` looks
  up the transport by `ep.id` and writes; an unknown id is dropped (the peer's endpoint is stale
  until it reconnects).
- **`wgengine.MuxEngine`** wraps the device: `NewMuxEngine(tun, privKey, logLevel)` (sets only
  `private_key`, brings the device up), `AddPeer(pub, allowedIP)` (incremental `IpcSet`, idempotent
  on reconnect, **kept across disconnects** so the WG session survives reconnects),
  `RemovePeer(pub)` (revocation), `Register/Deregister` (delegate to the bind), `Close`.
- **`core/server.Server` rewritten to multiplexed, replacing the per-client implementation**
  (keeping `notifyTransport`). `New(gate, sessions, store, cfg, tunDev)` builds one `MuxEngine` on a
  single injected `tun.Device`. `handle(conn)`: gate → (enroll | device) → session bind → ensure
  peer (`AddPeer`, allowed_ip = the device's `/32`) → allocate connID, wrap in `notifyTransport`,
  `Register` → `<-Done()` → `Deregister` → close conn. `Close()` closes tracked conns, waits on a
  handler `WaitGroup`, then `MuxEngine.Close()`.
- **Roaming & resume fall out for free:** WireGuard identifies peers by crypto, not endpoint; valid
  packets arriving on a new `muxEndpoint` re-point that peer's endpoint to the new connection. So a
  reconnect (new conn → new endpoint, session resumed via SESSION_BIND) resumes the tunnel with the
  device staying up — no re-handshake within the rekey window.

## 10. Admin API & web UI

- **Ownership:** the admin API lives in the `gvpn-server` process and is the single authority over
  the registry + live `MuxEngine`. Operations: list/add/remove users; set cap; open/close
  enrollment; list/revoke devices (revoke removes the live peer); mint/revoke share tokens; show
  **live connection status** (which devices currently have an active conn).
- **Web UI:** server-rendered Go `html/template` + a little vanilla JS — no SPA, no Node build. QR
  rendered inline. Pages: users list, user detail (devices + enrollment QR/link + share-token
  controls), device detail.
- **Exposure & auth:** bound to `127.0.0.1` only; operators reach it via an SSH port-forward. Login
  is an **admin password stored hashed** (argon2id/bcrypt) in the registry; sessions are
  cookie-based with a server-side secret. No admin surface on the public listeners.

## 11. Certificates

`gvpn-server gencert` generates self-signed certs for bootstrap/dev:

- **GOST cert** (VPN `:443`): generated via the OpenSSL-GOST engine — a new setup-time capability in
  `core/gosttls` (GOST keygen + self-sign; cgo). Presented only to gvpn clients, which **pin** it
  via the bundle (`caf` fingerprint or CA PEM), so a self-signed GOST cert is fully sufficient. A
  real org-trusted GOST cert can be swapped in later for stronger camouflage.
- **Standard cert** (public share page): self-signed via stdlib `crypto/x509` for dev. In
  **production the operator supplies** the standard cert/key via `server.yaml` (their own
  ACME/CDN/PKI), because phone browsers must trust it. **No ACME in the binary.**

## 12. `server.yaml` schema (target)

```yaml
server:
  listen: ":443"            # GOST TLS VPN listener
tls:                        # GOST server cert (self-signed/generated or org-trusted)
  cert: /etc/gvpn/gost.crt
  key:  /etc/gvpn/gost.key
wireguard:
  address: 10.100.0.1/24    # server TUN address + the enrollment subnet
  private_key_file: /etc/gvpn/wg.key
registry:
  path: /var/lib/gvpn/registry.json
  master_key_file: /etc/gvpn/master.key   # 32-byte AEAD master key (or GVPN_MASTER_KEY env)
share:                      # public standard-TLS enrollment share page
  listen: ":8443"
  cert: /etc/gvpn/share.crt # operator-provided in prod; gencert self-signed for dev
  key:  /etc/gvpn/share.key
  base_url: https://vpn.example.com:8443
admin:
  listen: 127.0.0.1:8081    # localhost only (SSH tunnel)
  # admin password hash lives in the registry, set via `gvpn-provision admin set-password`
```

## 13. Security considerations

- **Single bootstrap factor.** Whoever holds a user's enrollPSK can enroll devices up to the cap;
  mitigated by cap + open/closed + revoke + (for share links) TTL/revocation. Documented tradeoff
  of self-enrollment.
- **Master key compromise** = all PSKs compromised; keep it off the config and on a restricted file
  / secret store. PSKs are never written in plaintext.
- **Probe resistance preserved**: any AUTH failure (device or enroll) routes to the decoy with no
  distinguishing signal.
- **Admin surface** is localhost-only by default; the public share page exposes only a TTL'd token
  resolver, never admin operations.
- **No secret logging** anywhere (keys, PSKs, master key, share tokens, packets).

## 14. Testing strategy

- **provision**: AEAD round-trip; `AllocateIP` (sequential, skips used, reserves `.1`, subnet
  bounds, exhaustion error); read-write `FileStore` (add/remove/persist/atomic-rename, concurrent
  access under `-race`); user/device CRUD; bundle URI encode/decode; QR encode smoke test.
- **authgate**: token `kind` round-trip; enroll-token verify; device vs enroll routing; invalid →
  decoy.
- **wgengine**: `MuxBind` two-transport endpoint tagging + `Send` routing; `MuxEngine` add/remove
  peer.
- **server (netstack + plain TCP, `-race`)**: self-enroll-on-first-connect e2e (no pre-provision →
  device record created + tunnel up + HTTP over tunnel); multi-client concurrent (two users/devices
  on one device, correct routing); reconnect/roaming (drop + resume, same peer, device stays up).
- **binary / admin**: config parse; `gencert` produces loadable certs; admin API handlers (auth
  required, CRUD effects on registry + live peers); share-token TTL/revocation.
- All packages stay cgo-free except `gosttls`; `go list -deps ./server/` shows no netstack/gVisor.

## 15. Plan decomposition

Each plan is its own branch + PR, built bottom-up; resize when writing.

1. **Plan 9 — Identity & registry rework** *(write & implement first)*: user/device model;
   per-device + per-user enroll PSK; AEAD `Cipher` + master-key loading; `AllocateIP`; read-write
   persistent `FileStore` (`AddDevice`/`RemoveDevice`/users/lookups); `gvpn-provision` subcommands
   (`user add|list|remove`, `device add --user|list|revoke`) + bundle emission (file/link/QR).
   Pure unit/CLI tests. Touches merged `core/provision` + `core/cmd/gvpn-provision`. Existing dev
   registries are regenerated (no migration).
2. **Plan 10 — Enrollment protocol primitives**: AUTH token `kind`; `authgate` enroll validation +
   `Result{Kind,UserID}`; `DeviceStore.EnrollLookup`; the ENROLL frame/exchange (client + server
   helpers). Touches merged `frame`/`authgate`.
3. **Plan 11 — Multiplexed server core + enrollment handler**: `MuxBind`/`MuxEngine`; rewritten
   multiplexed `Server` (replaces per-client) wiring the enrollment handler (runtime `AddDevice` +
   live `AddPeer`). netstack/TCP e2e (self-enroll, multi-client, roaming).
4. **Plan 12 — `gvpn-server` binary**: `server.yaml`; `gosttls`→`net.Listener` adapter; real kernel
   TUN (`tun.CreateTUN`, CAP_NET_ADMIN); routing + iptables MASQUERADE; `sessions.Sweep()` ticker;
   master-key loading; in-process **admin API** foundation; **`gencert`** (GOST via gosttls/cgo +
   standard via stdlib).
5. **Plan 13 — Admin web UI + public share page**: localhost admin UI (Go templates, hashed-password
   login, live status, user/device/cap/enroll management, QR publishing) + the standard-TLS
   `/enroll/<token>` share page (TTL'd revocable tokens).

After this phase: client app TUN integration (Android `VpnService` / iOS Network Extension via
gomobile), and MTU/throughput validation against the §7 perf targets of the transport design.

## 16. Open items

- Confirm the chosen Go QR library (dependency-light, no cgo) during Plan 9.
- Decide the 16-byte **user id** representation backing `kind=ENROLL` tokens (stored per-user uuid
  vs. a hash of the handle) when writing Plan 10.
- Share-token default TTL value (Plan 13).
