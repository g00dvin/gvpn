package gosttls

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestGOSTGencertRoundTrip generates a self-signed GOST cert+key, then proves it
// works by standing up a GOST TLS listener with it and completing a handshake
// from a client that pins the same cert as its CA.
func TestGOSTGencertRoundTrip(t *testing.T) {
	if err := Init(); err != nil {
		t.Skipf("gost engine unavailable: %v", err)
	}
	dir := t.TempDir()
	cert := filepath.Join(dir, "gost.crt")
	key := filepath.Join(dir, "gost.key")
	if err := GenerateSelfSignedGOSTCert("localhost", cert, key, 365); err != nil {
		t.Fatalf("GenerateSelfSignedGOSTCert: %v", err)
	}

	ln, err := Listen("tcp", "127.0.0.1:0", Config{CertFile: cert, KeyFile: key})
	if err != nil {
		t.Fatalf("Listen with generated cert: %v", err)
	}
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := c.Read(buf); err != nil {
			srvErr <- err
			return
		}
		_, err = c.Write([]byte("pong"))
		srvErr <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cc, err := Dial(ctx, "tcp", ln.Addr().String(), Config{CAFile: cert, ServerName: "localhost"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cc.Close()
	if _, err := cc.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := cc.Read(got); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("got %q, want pong", got)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server: %v", err)
	}
	_ = net.Dial // keep net imported
}
