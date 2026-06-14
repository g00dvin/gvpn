package authgate

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/frame"
)

// TestEndToEndAuthenticated runs WriteAuth (client) against Gate.Handle (server)
// over a real TCP loopback, then confirms a following DATA frame reaches the
// data path.
func TestEndToEndAuthenticated(t *testing.T) {
	dev := [16]byte{9, 8, 7}
	psk := []byte("e2e-psk")
	g := NewGate(NewMapStore(map[[16]byte][]byte{dev: psk}), nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type out struct {
		r   Result
		err error
	}
	outc := make(chan out, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			outc <- out{err: err}
			return
		}
		r, err := g.Handle(conn)
		outc <- out{r: r, err: err}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := WriteAuth(conn, psk, dev); err != nil {
		t.Fatalf("WriteAuth: %v", err)
	}
	if err := frame.WriteFrame(conn, frame.TypeData, []byte("hello")); err != nil {
		t.Fatalf("WriteFrame data: %v", err)
	}

	got := <-outc
	if got.err != nil {
		t.Fatalf("gate: %v", got.err)
	}
	if !got.r.Authenticated || got.r.DeviceID != dev {
		t.Fatalf("auth=%v dev=%x", got.r.Authenticated, got.r.DeviceID)
	}
	got.r.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, payload, err := frame.ReadFrame(got.r.Conn)
	if err != nil {
		t.Fatalf("read data frame: %v", err)
	}
	if typ != frame.TypeData || string(payload) != "hello" {
		t.Fatalf("data frame = (%d,%q)", typ, payload)
	}
	got.r.Conn.Close()
}

// TestEndToEndDecoy confirms an unauthenticated client is served the decoy page.
func TestEndToEndDecoy(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen origin: %v", err)
	}
	defer origin.Close()
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				c.Read(buf)
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nDECOY"))
			}(c)
		}
	}()

	g := NewGate(NewMapStore(nil), TCPDecoy{Origin: origin.Addr().String()})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		g.Handle(conn)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.Write([]byte("GET / HTTP/1.1\r\nHost: gvpn\r\n\r\n"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read decoy response: %v", err)
	}
	if !bytes.Contains(buf[:n], []byte("DECOY")) {
		t.Fatalf("got %q, want the decoy page", buf[:n])
	}
}
