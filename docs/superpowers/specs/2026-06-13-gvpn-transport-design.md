# gvpn Transport Design — resolving spec-review findings

**Date:** 2026-06-13
**Status:** Approved (brainstorming) — pending implementation plan
**Inputs:** `spec.md`, `spec-review.md`

This design resolves the findings in `spec-review.md` while honoring the user's fixed constraints:
keep **GOST + TLS** as the transport security layer, and **accept TCP-in-TCP** (and its head-of-line
blocking) as a known, out-of-scope degradation.

---

## 1. Locked decisions

These three choices drive everything below and were each confirmed explicitly:

| Decision | Choice | Consequence |
|----------|--------|-------------|
| **GOST level** | Open GOST via **OpenSSL 3.x + gost-engine/provider** (CGO) | GOST TLS is a single native module behind a Go `net.Conn`; "unified Go core + one native TLS provider". Not state-certified (gost-engine, not CryptoPro/ViPNet). |
| **Threat model** | **Censorship circumvention** | Must resist passive DPI *and* active probing; traffic must be indistinguishable from ordinary HTTPS. |
| **Device auth** | **In-tunnel auth + decoy** | TLS-layer mTLS is dropped (it fingerprints to a prober); auth moves inside the tunnel; unauthenticated peers get a real decoy site. |

**Accepted, out of scope:** C1 (TCP-over-TCP meltdown) and M4 (single-TCP head-of-line blocking).
No UDP/QUIC carrier in this design. The one upside: TCP segmentation makes inner-MTU mistakes less
catastrophic than they'd be over UDP (see §6).

---

## 2. Revised architecture

```
                                   :443 / TCP
client  ──────── GOST TLS (server-auth only) ───────▶  TLS Listener
                                                          (OpenSSL 3.x + GOST provider, via CGO)
                                                              │
                                                              │ peek first frame after handshake
                                                              ▼
                                                       AUTH frame valid?
                                                        │            │
                                                   yes  │            │  no / HTTP / garbage
                                                        ▼            ▼
                                                  VPN data path   reverse-proxy to decoy origin
                                                  frames ⇄        (behave like a real website)
                                                  wireguard-go
```

Revised transport stack (vs. spec §2):

```
WireGuard Packet → Frame Protocol (typed) → GOST TLS (server-auth) → TCP/443
                                                  │
                                          in-tunnel AUTH gate → decoy fallback
```

Client and server share the same Go core; only the GOST TLS provider is native (CGO), compiled per
platform (server, Windows, and into mobile via gomobile).

---

## 3. Crypto stack & camouflage  *(resolves C2, M5; mitigates M6)*

- **GOST TLS engine.** OpenSSL 3.x with the GOST algorithms statically linked as a *provider*,
  wrapped behind a Go `net.Conn`-compatible type in one CGO package. This package is the *only*
  native dependency and is shared by server and all clients. Resolves C2 (Go stdlib has no GOST).
- **Server-auth only.** The server presents a real GOST server certificate for a plausible domain
  and **never** sends a TLS `CertificateRequest`. Active probers therefore see a normal HTTPS
  handshake — no client-cert demand to fingerprint.
- **Probe resistance (decoy).** A legitimate client's **first frame** is an `AUTH` frame carrying a
  high-entropy token: `HMAC(PSK, nonce || timestamp)` (replay-bound, unlinkable — deliberately *not*
  a fixed magic string, which would itself be a fingerprint). The server validates it:
  - valid → switch the connection to the VPN data path;
  - invalid / HTTP / arbitrary bytes (i.e. a prober or scanner) → **transparently reverse-proxy the
    connection to a configured decoy origin** and serve it as that website.
  Resolves M5. Within Russia, GOST HTTPS is expected cover traffic (gov/banking), strengthening the
  camouflage rather than standing out.
- **Double-crypto note (M6).** Every packet is still encrypted twice (GOST TLS + WireGuard). Where
  feasible, point wireguard-go at the same `libcrypto` to avoid shipping/initializing two crypto
  cores. Throughput is validated against §6 targets, not assumed.

## 4. Frame protocol  *(resolves C3, L1)*

The spec's length-only header cannot encode the heartbeat (§13), session-bind (§12), or auth that the
spec requires elsewhere — an internal contradiction. Replace it with a typed, versioned header:

```c
struct FrameHeader {
    uint8  version;   // protocol version, starts at 1
    uint8  type;      // see frame types below
    uint16 length;    // payload length, network byte order, validated before allocation
};
```

Frame types:

| Type | Meaning |
|------|---------|
| `DATA` | A WireGuard packet (the original spec payload). |
| `AUTH` | In-tunnel auth token; the first frame; the VPN-vs-decoy gate. |
| `HEARTBEAT` | Transport keepalive (§13) — now has a frame to ride in. |
| `SESSION_BIND` | Reconnect/resume token, rebinds an existing server session (§12). |
| `CONTROL` | Reserved for the future orchestrator (§18). |

- `uint16 length` matches the 65535 cap and removes the wasted 2 bytes of the spec's `uint32`
  (L1). Length is validated before allocation (buffer-overflow guard retained from spec §7).
- Resolves C3: heartbeat, auth, and session-bind now have a real on-wire encoding.

## 5. Transport adapter & reconnection  *(resolves M3, L3, L5)*

- **Reconnection is fully hidden behind `PacketTransport`.** The interface signature is unchanged,
  but the *contract* is fixed: on a dropped TCP/TLS connection, `ReadPacket`/`WritePacket` **block**
  (bounded backoff + a small outbound queue) while the adapter re-dials, repeats the GOST TLS
  handshake, re-sends `AUTH`, and sends a `SESSION_BIND` frame to rebind the existing server-side
  session. They return a terminal error **only** after `Close()` or when the reconnect budget is
  exhausted. wireguard-go therefore sees a stall, never an EOF, and its Noise session survives
  (WireGuard rekeys ~every 2 minutes regardless). Resolves M3.
- **Reconnect triggers (L3).** Roaming (Wi-Fi→LTE) is driven by OS network-change callbacks —
  Android `ConnectivityManager`, iOS `NWPathMonitor`, Windows `NotifyAddrChange` — not by waiting on
  the 30s heartbeat. The heartbeat is the backstop for silent-death detection only.
- **Keepalive layering (L5).** WireGuard `PersistentKeepalive` (peer liveness) + one transport
  `HEARTBEAT` (dead-TCP detection). OS-level TCP keepalive is explicitly disabled to avoid three
  overlapping timers.

## 6. Session, provisioning & identity  *(resolves M2, L2, L4)*

- **Session model (L2).** Drop `TLSConnection any` — the live connection is swapped on every
  reconnect and does not belong in the session. The session holds identity + resume state; the
  current connection lives in the adapter:
  ```go
  type Session struct {
      SessionID   string    // server-issued; referenced by SESSION_BIND
      DeviceID    string    // UUIDv4
      WGPublicKey string    // the registered peer key
      ResumeToken []byte    // binds a reconnect to this session
      LastSeen    time.Time
  }
  ```
- **Provisioning (M2).** With TLS-layer mTLS gone, a device bundle is: WG keypair, the `AUTH` PSK,
  the server domain/endpoint, the trust anchor for the server's GOST cert, and a `DeviceID` (UUIDv4)
  tying them together. Phase-1 enrollment is a server-side CLI (`gvpn-provision`) that generates the
  bundle and registers the device (WG pubkey + DeviceID + token) as a server peer. No orchestrator,
  but a real scriptable flow instead of a gap.
- **PKI framing (L4).** No client-cert CA is needed at all. The only PKI is the **server's** GOST
  cert — ideally a real publicly/org-trusted cert for the decoy domain, not a private CA. This
  removes the "no orchestrator but secretly a central CA" contradiction.

## 7. Mobile constraints & performance  *(resolves C4, M1, L6, L7; mitigates M6)*

- **iOS Network Extension memory (C4).** OpenSSL-GOST + wireguard-go + framing must fit the NE cap
  (~50 MB). **Action: spike the iOS NE memory footprint before committing the stack.** Mitigations:
  single static OpenSSL build (share `libcrypto` with wireguard-go where possible), strict buffer
  pooling, zero per-packet allocation on the data path. Fallback: feature-trim on iOS if the spike
  fails. This is the highest implementation risk and is de-risked first.
- **Performance targets (M1)** — replacing the spec's meaningless "idle" budget:
  - per-client throughput **≥ 50 Mbps** on a clean link;
  - server aggregate **≥ 500 Mbps** at 1000 connected clients (~50 concurrently active);
  - p95 added latency **≤ 30 ms**;
  - handshake rate **≥ 50/sec**;
  - server idle budget retained: **≤ 512 MB / ≤ 2 vCPU** at 1000 idle clients.
  (Starting points — to be reconciled with the real SLA.)
- **MTU (L6).** Pin an inner tunnel MTU accounting for WG + frame(4) + TLS record + TCP/IP overhead
  (≈ 1380–1400 inner). Document it rather than relying on PMTU discovery.
- **Windows GUI (L7).** Use **Wails** (Go-native, shares the core, single toolchain) unless a hard
  Qt requirement emerges.

---

## 8. Findings resolution matrix

| ID | Finding | Resolution |
|----|---------|-----------|
| C1 | TCP-over-TCP meltdown | **Accepted / out of scope** (user decision). |
| C2 | GOST TLS absent from Go stack | OpenSSL 3.x + GOST provider via CGO, behind a Go `net.Conn` (§3). |
| C3 | Frame can't carry control/heartbeat/session msgs | Typed + versioned frame header with `DATA/AUTH/HEARTBEAT/SESSION_BIND/CONTROL` (§4). |
| C4 | iOS NE memory vs userspace stack | Early memory spike + shared libcrypto + buffer pooling + iOS fallback (§7). |
| M1 | Performance target unmeasurable | Concrete throughput/latency/handshake targets (§7). |
| M2 | No provisioning flow | `gvpn-provision` CLI emits device bundle + registers peer (§6). |
| M3 | PacketTransport can't express reconnect | Contract: block across reconnects, terminal error only on Close (§5). |
| M4 | Single-TCP head-of-line blocking | **Accepted / out of scope** (user decision). |
| M5 | Threat model undefined / mTLS fingerprint | Censorship model chosen; server-auth TLS + decoy + in-tunnel auth (§3). |
| M6 | Userspace double-crypto vs budget | Shared libcrypto + validate against §7 targets. |
| L1 | uint32 length, uint16 max | `uint16 length` in typed header (§4). |
| L2 | `Session.TLSConnection any` lifecycle | Connection removed from Session; resume state only (§6). |
| L3 | 30s heartbeat too slow for roaming | OS network-change callbacks drive reconnect; heartbeat is backstop (§5). |
| L4 | "No orchestrator" but implicit CA | Only server GOST cert; no client-cert CA (§6). |
| L5 | Redundant keepalives | WG keepalive + one transport heartbeat; OS TCP keepalive disabled (§5). |
| L6 | MTU unspecified | Inner MTU ≈ 1380–1400, documented (§7). |
| L7 | "Wails or Qt" unresolved | Wails (§7). |

## 9. Deltas vs `spec.md` (sections to amend)

- **§2 / §8** — TLS-layer mTLS removed; transport is server-auth GOST TLS + in-tunnel auth + decoy.
- **§7** — frame header becomes versioned + typed.
- **§9 / §10** — per-device stored data drops client-cert fingerprint; adds AUTH PSK + ResumeToken;
  WG pubkey registration is the device-auth anchor.
- **§11** — `Session` struct revised (no `TLSConnection any`).
- **§14** — idle-only budget replaced with throughput/latency/handshake targets.
- **§17** — "no custom TLS stack": clarified — we ship OpenSSL+GOST (an existing, non-stdlib stack),
  not a hand-rolled one; the prohibition on *writing* crypto/TLS still holds.

## 10. Open risks / to validate before/early in implementation

1. **iOS NE memory spike** (C4) — go/no-go for the embedded OpenSSL-GOST + wireguard-go stack.
2. **OpenSSL 3.x GOST provider static-link** on iOS/Android (App Store forbids dynamic engine
   loading) — confirm the GOST provider builds statically for all targets.
3. **Throughput validation** (M1/M6) of the double-crypto + TCP-in-TCP path against §7 targets.
4. **Decoy origin realism** — the reverse-proxied site must be a plausible match for the GOST cert's
   domain, or the camouflage leaks.
