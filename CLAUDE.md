# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

Greenfield. The repository currently contains only `spec.md` — the authoritative technical
specification for a cross-platform VPN product. There is no code, `go.mod`, or build system yet.
`spec.md` is the source of truth; when implementing, treat its requirements and prohibitions as binding.

## What this product is

A VPN that tunnels **WireGuard traffic inside a GOST TLS connection over TCP/443**. The point of
TCP/443 + TLS is to make VPN traffic indistinguishable from ordinary HTTPS and to add Russian-crypto
(GOST) transport protection on top of standard WireGuard. One shared transport-layer codebase (Go)
serves the Linux server and all clients; there is no orchestrator in phase 1.

## The transport stack (core architecture)

Every WireGuard packet travels down this pipeline; this layering is the spine of the whole system:

```
WireGuard Packet  →  Frame Protocol  →  GOST TLS  →  TCP/443
```

- **WireGuard Engine** — embedded `wireguard-go`, talks to the world only through the
  `PacketTransport` interface (see below). It must not know anything about TLS, framing, or TCP.
- **Frame Protocol** — length-prefixed framing so packets can be recovered from a TCP byte stream.
  Header is a single `uint32 length` in **network byte order**, followed by the WireGuard packet.
  Max frame size **65535 bytes**; length must be validated before allocation/read (buffer-overflow guard).
- **Transport Adapter** — owns the TCP+TLS connection, implements `PacketTransport`, and is the
  only layer that deals with reconnection. It is independent of WireGuard.
- **GOST TLS** — TLS 1.3 (GOST TLS 1.3 if the chosen stack supports it), **mutual TLS (mTLS)** for
  device authentication. Client holds its cert + private key; server holds the CA cert.

The two key interfaces from the spec (WireGuard couples to the transport *only* through the first):

```go
type PacketTransport interface {
    ReadPacket() ([]byte, error)
    WritePacket([]byte) error
    Close() error
}

type Session struct {
    SessionID     string
    DeviceID      string
    WGPeer        string
    TLSConnection any
}
```

Server and client share the same component layering: `Session Manager → Transport Adapter →
WireGuard Engine`, with a `TLS Listener` on the server and a `Tunnel Manager` + UI on the client.

## Hard constraints (do not violate)

These are explicit prohibitions in the spec. Reach for an existing library before writing anything
in these areas, and stop and flag if a task seems to require crossing one:

- **No custom cryptography** — no custom VPN protocol, key exchange, TLS stack, or crypto algorithms.
- **WireGuard stays standard** — do not replace its crypto or key exchange; use `wireguard-go` as an
  embedded library. Do **not** shell out to `wg` or `wg-quick` as external processes.
- **Never disable certificate validation.**
- **Never log** private keys, WireGuard packet contents, or TLS session keys (log levels: ERROR,
  WARN, INFO, DEBUG, TRACE).

## Behavioral requirements that cut across layers

- **Reconnection**: automatic; must survive client IP changes (e.g. Wi-Fi → LTE) by re-establishing
  TCP, resuming TLS, and re-binding the existing `Session` — VPN state is preserved, not reset.
- **Keepalive**: WireGuard `PersistentKeepalive` *plus* a transport-layer heartbeat every 30s.
- **Future compatibility**: keep public interfaces extensible for a later orchestrator, multi-server,
  device management, certificate rotation, and load balancing — even though none ship in phase 1.
- **Performance budget (server)**: 1000 clients within ≤512 MB RAM and ≤2 vCPU at idle.

## Identity & config

- Each device has a UUIDv4 **Device ID**. Server stores per device: Device ID, client certificate
  fingerprint, WireGuard public key.
- Server config is YAML (`server.listen`, `tls.{cert,key,ca}`, `wireguard.address`).

## Tech stack (per spec — not yet scaffolded)

- **Server**: Go ≥ 1.24, Linux (Debian 12+ / Ubuntu 24+; RED OS & Astra Linux later).
- **Windows client**: Wails or Qt GUI, Go backend.
- **Android**: Kotlin UI + `VpnService`, Go backend via `gomobile`.
- **iOS**: SwiftUI + Network Extension, Go backend via `gomobile`.

The Go transport/WireGuard core is shared across server and all clients (compiled into mobile via
`gomobile`), so keep it free of platform-specific or UI dependencies.

## MVP done criteria

Server accepts TLS connections; client completes mTLS; WireGuard runs through the transport adapter;
IP traffic flows through the VPN; automatic reconnection works; Windows, Android, and iOS clients
function; no known memory leaks or crashes under load testing.
