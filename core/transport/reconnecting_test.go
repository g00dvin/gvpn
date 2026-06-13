package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/frame"
)

// pipeDialer hands out net.Pipe connections and exposes the server ends on
// serverC. It can be told to fail the first failN dials.
type pipeDialer struct {
	serverC chan net.Conn
	mu      sync.Mutex
	dials   int
	failN   int
}

func newPipeDialer(failN int) *pipeDialer {
	return &pipeDialer{serverC: make(chan net.Conn), failN: failN}
}

func (d *pipeDialer) dial(ctx context.Context) (io.ReadWriteCloser, error) {
	d.mu.Lock()
	d.dials++
	fail := d.failN > 0
	if fail {
		d.failN--
	}
	d.mu.Unlock()
	if fail {
		return nil, errors.New("pipeDialer: simulated dial failure")
	}
	cli, srv := net.Pipe()
	d.serverC <- srv
	return cli, nil
}

func (d *pipeDialer) dialCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

func mustReadFrame(t *testing.T, r io.Reader, wantType frame.Type, wantPayload string) {
	t.Helper()
	typ, p, err := frame.ReadFrame(r)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if typ != wantType || string(p) != wantPayload {
		t.Fatalf("frame = (%d,%q), want (%d,%q)", typ, p, wantType, wantPayload)
	}
}

func TestReconnectingHappyPath(t *testing.T) {
	d := newPipeDialer(0)
	tr := NewReconnectingTransport(ReconnectingConfig{
		Dialer:       d.dial,
		SessionToken: []byte("sess-1"),
		MinBackoff:   time.Millisecond,
		MaxBackoff:   5 * time.Millisecond,
	})
	defer tr.Close()

	// First WritePacket triggers the lazy dial; run it in a goroutine because
	// net.Pipe is synchronous.
	writeErr := make(chan error, 1)
	go func() { writeErr <- tr.WritePacket([]byte("hello")) }()

	srv := <-d.serverC
	mustReadFrame(t, srv, frame.TypeSessionBind, "sess-1")
	mustReadFrame(t, srv, frame.TypeData, "hello")
	if err := <-writeErr; err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	// Server -> client DATA frame, read via ReadPacket.
	// net.Pipe is synchronous: the server write must run concurrently with the
	// client read so neither side deadlocks waiting for the other.
	go func() {
		if err := frame.WriteFrame(srv, frame.TypeData, []byte("world")); err != nil {
			t.Error(err)
		}
	}()
	got, err := tr.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if string(got) != "world" {
		t.Fatalf("packet = %q, want %q", got, "world")
	}

	if d.dialCount() != 1 {
		t.Fatalf("dials = %d, want 1", d.dialCount())
	}
}
