# Spec Review — gvpn

Technical analysis of `spec.md`: mistakes, logical contradictions, weak technical choices, and
dev-stack risks. Severity is from the perspective of "will this block or break the MVP."

Reviewed against: WireGuard's design constraints, TLS/GOST availability, Go + gomobile realities,
and mobile platform limits.

---

## TL;DR

The crypto-conservative core (standard WireGuard, standard TLS, a clean `PacketTransport`
abstraction) is sound. The risks are concentrated in four places:

1. **WireGuard-over-TCP** is mandated as the *only* transport — this is a known anti-pattern (TCP-over-TCP meltdown).
2. **GOST TLS in Go** essentially does not exist in the stdlib, yet GOST + a unified Go codebase are both hard requirements — a direct contradiction.
3. **The frame protocol cannot carry the heartbeat / session-bind / control messages** the spec itself requires elsewhere — an internal contradiction.
4. **iOS Network Extension memory limits** vs. userspace WireGuard + userspace TLS is a real "may not fit" risk.

Plus: the spec defines *no throughput target* and *no device-provisioning flow*, and leaves the
*threat model undefined*, so several requirements can't actually be evaluated as written.

---

## Critical

### C1. TCP-only transport → TCP-over-TCP meltdown
**§2 (transport stack), §6, §19.** WireGuard is deliberately UDP-only. Here it is wrapped in
TLS-over-TCP with no UDP path. Tunneling a reliable transport inside another reliable transport
stacks two retransmission/congestion-control loops; under packet loss the inner and outer timers
fight each other and throughput collapses ("TCP meltdown"). Inner TCP flows (most user traffic) make
this worse.
- **Impact:** poor/unstable throughput on lossy links (mobile, the exact target in §12).
- **Recommendation:** treat TCP/443 as a *fallback* obfuscation transport and add a primary
  UDP/QUIC path. If TCP-only is a hard censorship requirement, prefer a QUIC-based carrier (UDP,
  no HOL blocking) over raw TLS/TCP, and document the loss-vs-throughput tradeoff explicitly. At
  minimum, the spec must acknowledge this is a known degradation mode.

### C2. GOST TLS is not available in the chosen stack
**§1 (goal), §2, §4 (Go ≥1.24), §8.** Go's `crypto/tls` has **no GOST support at all**, and the
spec itself hedges ("GOST TLS 1.3 *if supported by the selected stack*"). GOST cipher suites are
standardized for **TLS 1.2** (RFC 9189); GOST-in-TLS-1.3 is draft/limited. So the §1 goal ("support
Russian crypto through GOST TLS"), the §8 requirement, and the §4 "Go server / unified codebase"
requirement cannot all hold simultaneously with pure Go.
- **Impact:** the headline feature is unimplementable as specified. Meeting it forces CGO bindings
  to OpenSSL+gost-engine or CryptoPro CSP — which breaks "unified Go codebase" and severely
  complicates gomobile builds (see C4 / S4).
- **Recommendation:** decide and document *now*: (a) which GOST provider (CryptoPro CSP vs.
  OpenSSL gost-engine), (b) TLS 1.2-GOST vs. 1.3 (likely 1.2 in practice), (c) per-platform
  availability and licensing, and (d) whether "GOST" is mandatory for MVP or can be a pluggable
  cipher behind a standard-TLS MVP. Also reconcile the §17 prohibition "no custom TLS stack" with
  the fact that you'll be shipping a non-stdlib TLS engine.

### C3. Frame protocol cannot carry control/heartbeat/session messages
**§7 vs. §11, §12, §13.** The frame is *only* `uint32 length` + WireGuard payload — there is **no
type/version field**. But the spec also requires a transport **heartbeat every 30s** (§13), a
**session-bind** step after reconnect (§12), and forward-compat **control** for an orchestrator
(§18). None of those are WireGuard packets, so there is no way to encode them in the frame as
specified. This is an internal contradiction.
- **Recommendation:** add a `type` (and `version`) byte to the frame header, e.g.
  `{ uint8 version; uint8 type; uint16 length }` (also fixes C-low-1). Define frame types: DATA,
  HEARTBEAT, SESSION_BIND, and reserve a range for control. Note this also gives you the
  session-resume token channel C2/§12 needs.

### C4. iOS Network Extension memory budget vs. userspace stack
**§4 (iOS), §5 (wireguard-go), §14.** iOS runs the VPN inside a Network Extension process with a
hard, low memory cap (~15 MB historically, ~50 MB on newer OSes). WireGuard's own iOS app already
fights this limit running `wireguard-go` in the NE. This spec adds **userspace GOST TLS + framing +
double crypto** inside that same capped process.
- **Impact:** the iOS client (an MVP completion criterion, §19) may not fit in the NE memory budget.
- **Recommendation:** prototype the iOS NE memory footprint early (spike before committing). Keep
  per-connection buffers tiny, avoid per-packet allocations, and budget GOST/TLS state carefully.
  Have a fallback plan (e.g. kernel-assisted paths, or trimming features on iOS).

---

## Medium

### M1. Performance target is unmeasurable / missing throughput
**§14.** The only budget is "1000 clients, ≤512 MB, ≤2 vCPU **for idle connections**." Idle
connections are nearly free; this says almost nothing. There is **no throughput target** (Mbps/Gbps),
no concurrent-handshake rate, no connection-setup rate, and no latency bound — the metrics that
actually matter for a VPN and that interact with the userspace-WG + userspace-TLS + double-crypto
cost.
- **Recommendation:** add active-traffic targets (e.g. aggregate Mbps at N active clients, p95
  added latency, handshakes/sec) and validate against userspace overhead before locking the stack.

### M2. No device-provisioning / enrollment flow
**§8, §9, §10, §18.** mTLS needs a per-device client cert + key, and WireGuard needs a per-device
keypair registered as a server peer. The spec describes what the server *stores* but never how a
device *gets* enrolled — and §12 explicitly defers "Device Management" and "Certificate Rotation."
With "no orchestrator in phase 1," initial provisioning of 1000 devices is undefined.
- **Recommendation:** define a minimal phase-1 enrollment path (even if manual/scripted): CSR or
  cert issuance, WG keygen, and peer registration on the server. Note that mTLS already implies a
  **central CA**, which somewhat contradicts the "no centralized component" framing (see L4).

### M3. `PacketTransport` can't express reconnection semantics → WireGuard teardown risk
**§5 interface vs. §12.** `ReadPacket()/WritePacket()` return plain `error`. During a transient
reconnect (Wi-Fi→LTE), if the transport returns an error, `wireguard-go` may treat it as fatal and
tear down. The interface gives no way to distinguish "transient, retrying" from "closed."
- **Recommendation:** specify that the Transport Adapter **hides** reconnection — `ReadPacket`
  blocks (or returns a retryable sentinel) across reconnects and only returns a terminal error on
  `Close()`. Document this contract; it's the crux of "preserve VPN state" (§12).

### M4. Single TCP connection → head-of-line blocking
**§2, §6.** All of a client's tunneled flows share one TCP stream. One lost segment stalls *every*
inner flow until retransmit — on top of C1. Multiplexing many user TCP flows over a single carrier
TCP is the worst case.
- **Recommendation:** another argument for a QUIC carrier (independent streams, no HOL blocking).
  If staying on TCP, at least acknowledge the limitation; per-client multiple connections add
  complexity without fixing the core meltdown.

### M5. Threat model is undefined
**§1, §2, §8.** TCP/443 + TLS + GOST strongly implies **censorship circumvention** (look like
HTTPS). But the design choices only make sense for *transport confidentiality*, not active-probing
resistance: a server on :443 that **demands a client certificate (mTLS)** and doesn't serve real
HTTP is trivially fingerprintable by an active prober, and fixed 30s heartbeats add a traffic
signature. If the goal is anti-censorship, mTLS-on-443 is weak obfuscation; if it's corporate
transport security, it's fine.
- **Recommendation:** state the threat model explicitly. If anti-censorship is in scope, reconsider
  mTLS-on-443 and constant-rate heartbeats, and look at established obfuscation transports.

### M6. Userspace double-crypto vs. the resource budget
**§5, §14.** Every packet is encrypted/decrypted twice (GOST TLS *and* WireGuard's
ChaCha20-Poly1305), both in userspace, both per-connection. `wireguard-go` is already markedly
slower and heavier than kernel WireGuard.
- **Recommendation:** benchmark the doubled userspace crypto path early against M1's (to-be-added)
  throughput target; the 512 MB / 2 vCPU figure is plausible only because it's scoped to *idle*.

---

## Low / design smells

- **L1. `uint32 length` but max 65535.** The header field is 32-bit while the cap fits in 16 bits —
  2 wasted bytes/frame and a larger malicious length to guard against. Folding this into the typed
  header from C3 (`uint16 length`) fixes it.
- **L2. `Session.TLSConnection any`.** `any`/`interface{}` discards type safety, and storing the
  live TLS connection in a struct that must *survive* TLS reconnection (§12) muddies the lifecycle.
  Use a concrete connection type and treat it as a swappable/mutable field with clear ownership.
- **L3. 30s heartbeat is slow for mobile roaming.** §12 wants fast Wi-Fi→LTE recovery, but a 30s
  transport heartbeat means up to 30s of dead tunnel before detection. Drive reconnection from OS
  network-change callbacks (Android `ConnectivityManager`, iOS `NWPathMonitor`), with the heartbeat
  as a backstop.
- **L4. "No orchestrator" but implicit central CA.** mTLS requires a CA to issue/verify certs —
  a centralized PKI component. Reconcile the wording (ties into M2).
- **L5. Redundant keepalives.** WireGuard `PersistentKeepalive` + transport heartbeat + TCP
  keepalive = three mechanisms. Defensible for fast dead-connection detection, but justify it
  rather than running all three blindly.
- **L6. MTU unspecified.** Encapsulation overhead (WG + frame + TLS record + TCP/IP) is significant;
  inner tunnel MTU and PMTU handling are never mentioned. Specify the inner MTU.
- **L7. "Wails or Qt" unresolved.** These imply completely different toolchains/skill sets (web
  frontend vs. C++/Qt) and neither shares the "unified" Go transport beyond the backend. Pick one.

---

## What's right (keep it)

- Not rolling custom crypto — standard WireGuard + standard TLS, with explicit §17 prohibitions.
- The `PacketTransport` abstraction cleanly decouples WireGuard from transport (just needs the
  reconnect-semantics fix in M3).
- Clean layered architecture shared between client and server.
- Forbidding `wg`/`wg-quick` subprocesses in favor of embedded `wireguard-go`.
- Explicit "never log keys / packets / session keys" (§15).

---

## Suggested priority order before coding

1. Resolve **C2** (GOST provider + platform/licensing) — it dictates the entire crypto stack and may break "unified Go."
2. Decide **C1/M4** transport (accept TCP-meltdown as fallback-only, or adopt QUIC).
3. Fix the **C3** frame format (typed/versioned) — cheap now, expensive later.
4. Spike **C4** (iOS NE memory) and **M6** (double-crypto throughput) to de-risk §14/§19.
5. Add the missing **M1** throughput targets, **M2** enrollment flow, and **M5** threat model to the spec.
