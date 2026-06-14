package gosttls

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestGOSTTLSLoopbackEcho stands up a GOST TLS listener, dials it, and verifies
// a byte payload round-trips through the encrypted tunnel and that the
// negotiated cipher is actually a GOST suite (not a fallback).
func TestGOSTTLSLoopbackEcho(t *testing.T) {
	cfg := testConfig(t) // generates a fresh GOST cert; serves as cert and CA.

	ln, err := Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	var serverErr error
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			serverErr = err
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			serverErr = err
			return
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			serverErr = err
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := Dial(ctx, "tcp", ln.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	want := []byte("hello gost tls")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo mismatch: got %q want %q", got, want)
	}

	if name := CipherName(conn); !strings.Contains(name, "GOST") {
		t.Fatalf("negotiated cipher %q does not contain GOST", name)
	}

	wg.Wait()
	if serverErr != nil {
		t.Fatalf("server goroutine: %v", serverErr)
	}
}
