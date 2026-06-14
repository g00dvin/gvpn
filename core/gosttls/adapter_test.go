package gosttls

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/transport"
)

// TestDialGOSTTLSAdapter verifies the adapter satisfies transport.Dialer and
// that the connection it yields carries application data end to end.
func TestDialGOSTTLSAdapter(t *testing.T) {
	cfg := testConfig(t)

	ln, err := Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write(buf[:n])
	}()

	var dialer transport.Dialer = DialGOSTTLS("tcp", ln.Addr().String(), cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rwc, err := dialer(ctx)
	if err != nil {
		t.Fatalf("dialer: %v", err)
	}
	defer rwc.Close()

	if _, err := rwc.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(rwc, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("echo = %q, want %q", got, "ping")
	}
	wg.Wait()
}

// TestDialGOSTTLSErrorIsNilInterface ensures a failed dial returns a true nil
// io.ReadWriteCloser, not a non-nil interface wrapping a nil *Conn.
func TestDialGOSTTLSErrorIsNilInterface(t *testing.T) {
	cfg := testConfig(t)
	dialer := DialGOSTTLS("tcp", "127.0.0.1:1", cfg) // port 1: expect refusal

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rwc, err := dialer(ctx)
	if err == nil {
		if rwc != nil {
			rwc.Close()
		}
		t.Skip("unexpected successful connect to 127.0.0.1:1")
	}
	if rwc != nil {
		t.Fatalf("on error the ReadWriteCloser must be a nil interface, got %T", rwc)
	}
}
