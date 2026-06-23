package gosttls

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCAPEMVerifiesGeneratedCert(t *testing.T) {
	if err := Init(); err != nil {
		t.Skipf("gost engine unavailable: %v", err)
	}
	dir := t.TempDir()
	cert := filepath.Join(dir, "gost.crt")
	key := filepath.Join(dir, "gost.key")
	if err := GenerateSelfSignedGOSTCert("localhost", cert, key, 365); err != nil {
		t.Fatalf("GenerateSelfSignedGOSTCert: %v", err)
	}
	caPEM, err := os.ReadFile(cert)
	if err != nil {
		t.Fatalf("read cert pem: %v", err)
	}

	ln, err := Listen("tcp", "127.0.0.1:0", Config{CertFile: cert, KeyFile: key})
	if err != nil {
		t.Fatalf("Listen: %v", err)
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
	cc, err := Dial(ctx, "tcp", ln.Addr().String(), Config{CAPEM: string(caPEM), ServerName: "localhost"})
	if err != nil {
		t.Fatalf("Dial with CAPEM: %v", err)
	}
	defer cc.Close()
	if _, err := cc.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := cc.Read(got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("got %q, want pong", got)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestClientCtxRequiresSomeCA(t *testing.T) {
	if err := Init(); err != nil {
		t.Skipf("gost engine unavailable: %v", err)
	}
	_, err := Dial(context.Background(), "tcp", "127.0.0.1:1", Config{ServerName: "x"})
	if err == nil {
		t.Fatal("Dial with no CA configured: want error")
	}
}
