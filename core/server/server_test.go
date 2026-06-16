package server

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/session"
	"golang.zx2c4.com/wireguard/tun"
)

// An unauthenticated connection must be closed by the gate and must never reach
// the TUN factory / WireGuard setup; Server.Close must then return cleanly.
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
	srv := New(gate, sessions, store, Config{}, func() (tun.Device, error) {
		t.Error("TunFactory must not be called for an unauthenticated connection")
		return nil, nil
	})

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
