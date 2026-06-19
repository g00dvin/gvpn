package server

import (
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/session"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// An unauthenticated connection must be closed by the gate and never reach the
// WireGuard data path; Server.Close must then return cleanly.
func TestServerClosesUnauthenticatedConn(t *testing.T) {
	c, err := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	store, err := provision.NewFileStore(filepath.Join(t.TempDir(), "empty.json"), c)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	gate := authgate.NewGate(store, nil) // nil decoy => unauthenticated conns are closed
	sessions := session.NewManager(time.Minute)
	tunDev, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.100.0.1")}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	srv, err := New(gate, sessions, store, Config{}, tunDev)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// Not a valid AUTH frame -> the gate closes the connection.
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 16)); err == nil {
		t.Fatal("server did not close the unauthenticated connection")
	}

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// A client that authenticates but then stalls (never sends the post-gate frame)
// must have its handler released by the handshake deadline, so the connection is
// closed and Server.Close does not hang on the handler wait.
func TestServerStalledHandlerTimesOutAndCloseReturns(t *testing.T) {
	old := handshakeTimeout
	handshakeTimeout = 300 * time.Millisecond
	defer func() { handshakeTimeout = old }()

	c, err := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	store, err := provision.NewFileStore(filepath.Join(t.TempDir(), "registry.json"), c)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	user, enrollPSK, err := store.AddUser("staller")
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	userID, _ := provision.ParseDeviceID(user.ID)

	tunDev, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.100.0.1")}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	srv, err := New(authgate.NewGate(store, nil), session.NewManager(time.Minute), store, Config{}, tunDev)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// Authenticate, then stall: never send the enroll request frame.
	if err := authgate.WriteEnrollAuth(conn, enrollPSK, userID); err != nil {
		t.Fatalf("WriteEnrollAuth: %v", err)
	}
	// The handshake deadline fires and the server closes the stalled handler.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 16)); err == nil {
		t.Fatal("server did not close the stalled handler after the handshake deadline")
	}

	// Close must return promptly (the handler was already released by the deadline).
	done := make(chan error, 1)
	go func() { done <- srv.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung waiting on a stalled handler")
	}
}
