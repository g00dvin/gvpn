// Package goste2e holds integration tests that exercise a real GOST-TLS
// handshake plus the gvpn AUTH + SESSION_BIND control protocol against the gost
// engine. It has no non-test API; it exists so `go test ./...` and the Android
// emulator job can compile and run the handshake e2e.
package goste2e
