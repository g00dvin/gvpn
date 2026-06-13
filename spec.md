# Technical Specification for AI Development Agent

## Project

Development of a cross-platform VPN product using:

- WireGuard as the VPN engine;
- GOST TLS as the transport security layer;
- TCP/443 as the transport channel;
- Linux server;
- Windows, Android, and iOS clients;
- no centralized orchestrator in the first phase.

---

# 1. Project Goals

Create a VPN system with the following properties:

- use of the proven WireGuard VPN protocol;
- encapsulation of WireGuard traffic inside a TLS connection;
- support for Russian cryptographic algorithms through GOST TLS;
- operation over TCP/443;
- ability to introduce an orchestrator in the future without changing the transport protocol;
- a unified transport-layer codebase.

---

# 2. Architectural Constraints

## Mandatory Requirements

### WireGuard

WireGuard must be used as the primary VPN engine.

The following are prohibited:

- implementing a custom VPN protocol;
- implementing a custom key exchange mechanism;
- replacing WireGuard cryptography with custom cryptography.

### Transport

The following stack must be used:

```text
WireGuard Packet
      ↓
Frame Protocol
      ↓
GOST TLS
      ↓
TCP/443
```

### Cryptography

Use:

- WireGuard for VPN encryption;
- GOST TLS for transport protection.

The following are prohibited:

- implementing custom cryptographic protocols;
- implementing custom key exchange mechanisms.

### TLS

Use:

- TLS 1.3;
- GOST TLS 1.3 (if supported by the selected stack);
- mutual TLS (mTLS) for device authentication.

---

# 3. Overall Architecture

```text
+--------------------------------------+
| Client                               |
+--------------------------------------+
| UI                                   |
| Tunnel Manager                       |
| Session Manager                      |
| Transport Adapter                    |
| WireGuard Engine                     |
+-------------------+------------------+
                    |
                    |
              TCP/443
                    |
+-------------------v------------------+
| Server                               |
+--------------------------------------+
| TLS Listener                         |
| Session Manager                      |
| Transport Adapter                    |
| WireGuard Engine                     |
+--------------------------------------+
```

---

# 4. Technology Stack

## Server

Language:

```text
Go >= 1.24
```

Operating System:

```text
Linux
```

Supported distributions:

- Debian 12+
- Ubuntu 24+
- RED OS (future)
- Astra Linux (future)

## Client

### Windows

GUI:

```text
Wails
or
Qt
```

Backend:

```text
Go
```

### Android

UI:

```text
Kotlin
```

VPN Service:

```text
VpnService API
```

Backend:

```text
gomobile
```

### iOS

UI:

```text
SwiftUI
```

VPN:

```text
Network Extension
```

Backend:

```text
gomobile
```

---

# 5. WireGuard Engine

## Requirement

Use:

```text
wireguard-go
```

as an embedded component.

The following are prohibited:

```text
wg
wg-quick
```

as external processes.

## Transport Abstraction

Create the following interface:

```go
type PacketTransport interface {
    ReadPacket() ([]byte, error)
    WritePacket([]byte) error
    Close() error
}
```

WireGuard must interact exclusively through this interface.

---

# 6. Transport Layer

## General Requirements

The transport layer must:

- operate over TCP;
- operate over TLS;
- support connection recovery;
- remain independent from WireGuard.

---

# 7. Frame Protocol

Each WireGuard packet must be transmitted inside a frame.

Format:

```c
struct FrameHeader {
    uint32_t length;
}
```

Payload:

```text
WireGuard Packet
```

Requirements:

- network byte order;
- maximum frame size of 65535 bytes;
- protection against buffer overflows.

---

# 8. TLS

Use:

```text
mTLS
```

## Client

Stores:

```text
Client Certificate
Client Private Key
```

## Server

Stores:

```text
CA Certificate
```

---

# 9. Device Identification

Each device has:

```text
Device ID
```

UUIDv4.

The server stores:

```text
Device ID
Client Certificate Fingerprint
WireGuard Public Key
```

---

# 10. WireGuard Configuration

Server-side:

```text
WG Public Key
WG AllowedIPs
```

Client-side:

```text
WG Private Key
WG Address
```

---

# 11. Session Management

A session contains:

```go
type Session struct {
    SessionID     string
    DeviceID      string
    WGPeer        string
    TLSConnection any
}
```

---

# 12. Reconnection

Requirements:

- automatic reconnection;
- support for client IP address changes;
- preservation of VPN state.

Workflow:

```text
Wi-Fi → LTE

TCP Disconnect
       ↓
Reconnect
       ↓
TLS Resume
       ↓
Bind Session
```

---

# 13. Keepalive

Use:

### WireGuard

Standard:

```text
PersistentKeepalive
```

### Transport Layer

Additional:

```text
Heartbeat
```

every 30 seconds.

---

# 14. Performance

Target metrics:

### Server

```text
1000 clients
```

Memory consumption:

```text
≤ 512 MB
```

CPU usage:

```text
≤ 2 vCPU
```

for idle connections.

---

# 15. Logging

Levels:

```text
ERROR
WARN
INFO
DEBUG
TRACE
```

The following must never be logged:

- private keys;
- WireGuard packet contents;
- TLS session keys.

---

# 16. Configuration

Format:

```yaml
server:
  listen: ":443"

tls:
  cert: server.crt
  key: server.key
  ca: ca.crt

wireguard:
  address: 10.100.0.1/24
```

---

# 17. Security

The following are prohibited:

- implementing custom cryptographic algorithms;
- implementing a custom TLS stack;
- implementing a custom key exchange mechanism;
- disabling certificate validation.

---

# 18. Future Compatibility

All public interfaces must be designed to accommodate:

```text
Orchestrator
Multi-server
Device Management
Certificate Rotation
Load Balancing
```

---

# 19. MVP Completion Criteria

The MVP is considered complete when:

- the Linux server accepts TLS connections;
- the client successfully completes mTLS authentication;
- WireGuard operates through the transport adapter;
- IP traffic is transmitted through the VPN;
- automatic reconnection works;
- the Windows client is functional;
- the Android client is functional;
- the iOS client is functional;
- no known memory leaks exist;
- no known crashes occur during load testing.

---

# 20. Repository and CI/CD

## Hosting

The project is hosted on GitHub as a single **monorepo** containing the shared Go
core, the Linux server, and all clients:

```text
core/            shared Go transport core (framing, transport adapter, GOST conn,
                 wireguard-go integration); bound to mobile via gomobile
server/          Linux server (imports core)
client/windows/  Wails client (Go + frontend, imports core)
client/android/  Kotlin app consuming the gomobile .aar built from core
client/ios/      SwiftUI app consuming the gomobile .xcframework built from core
```

## Continuous Integration

A GitHub Actions workflow must build every part of the project on each push and
pull request:

- shared Go core — vet + tests;
- Linux server — Go build;
- Windows client — Wails build;
- Android client — gomobile `.aar` + Gradle build;
- iOS client — gomobile `.xcframework` + Xcode build (macOS runner).

Requirements:

- the GOST TLS native dependency (OpenSSL 3.x + GOST provider) is provisioned in CI;
- build artifacts are published per component;
- until a component's code exists, its job detects the missing module and skips
  cleanly, so the pipeline stays green during early development.
