package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
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

func TestReconnectingReconnectsAfterDrop(t *testing.T) {
	d := newPipeDialer(0)
	tr := NewReconnectingTransport(ReconnectingConfig{
		Dialer:       d.dial,
		SessionToken: []byte("sess"),
		MinBackoff:   time.Millisecond,
		MaxBackoff:   5 * time.Millisecond,
	})
	defer tr.Close()

	// First connection.
	go func() { tr.WritePacket([]byte("p1")) }()
	srv1 := <-d.serverC
	mustReadFrame(t, srv1, frame.TypeSessionBind, "sess")
	mustReadFrame(t, srv1, frame.TypeData, "p1")

	// Drop the connection from the server side.
	srv1.Close()

	// The next write must transparently reconnect (second dial) and resend bind.
	writeErr := make(chan error, 1)
	go func() { writeErr <- tr.WritePacket([]byte("p2")) }()
	srv2 := <-d.serverC
	mustReadFrame(t, srv2, frame.TypeSessionBind, "sess")
	mustReadFrame(t, srv2, frame.TypeData, "p2")
	if err := <-writeErr; err != nil {
		t.Fatalf("WritePacket after drop: %v", err)
	}
	if got := d.dialCount(); got != 2 {
		t.Fatalf("dials = %d, want 2", got)
	}
}

func TestReconnectingCloseUnblocksBlockedRead(t *testing.T) {
	d := newPipeDialer(0)
	tr := NewReconnectingTransport(ReconnectingConfig{
		Dialer:     d.dial,
		MinBackoff: time.Millisecond,
		MaxBackoff: 5 * time.Millisecond,
	})

	errc := make(chan error, 1)
	go func() {
		_, err := tr.ReadPacket()
		errc <- err
	}()

	// No SessionToken => no bind frame; the client just blocks reading.
	<-d.serverC
	time.Sleep(10 * time.Millisecond) // ensure ReadPacket is parked in ReadFrame

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errc:
		if err != ErrClosed {
			t.Fatalf("err = %v, want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadPacket did not return after Close")
	}
}

func TestReconnectingCloseUnblocksBackoff(t *testing.T) {
	d := newPipeDialer(1 << 30) // every dial fails => stuck in backoff
	tr := NewReconnectingTransport(ReconnectingConfig{
		Dialer:     d.dial,
		MinBackoff: 5 * time.Millisecond,
		MaxBackoff: 10 * time.Millisecond,
	})

	errc := make(chan error, 1)
	go func() {
		_, err := tr.ReadPacket()
		errc <- err
	}()
	time.Sleep(20 * time.Millisecond) // let it enter the backoff loop

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errc:
		if err != ErrClosed {
			t.Fatalf("err = %v, want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadPacket did not return after Close during backoff")
	}
}

// Fix 1: Close must cancel an in-flight dial, not wait out DialTimeout.
func TestReconnectingCloseUnblocksMidDial(t *testing.T) {
	dialStarted := make(chan struct{}, 1)
	dialer := func(ctx context.Context) (io.ReadWriteCloser, error) {
		select {
		case dialStarted <- struct{}{}:
		default:
		}
		<-ctx.Done() // block until the dial context is cancelled
		return nil, ctx.Err()
	}
	tr := NewReconnectingTransport(ReconnectingConfig{
		Dialer:      dialer,
		DialTimeout: 10 * time.Second, // long; Close must beat this
	})

	errc := make(chan error, 1)
	go func() {
		_, err := tr.ReadPacket()
		errc <- err
	}()
	<-dialStarted // a dial is now in flight

	start := time.Now()
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errc:
		if err != ErrClosed {
			t.Fatalf("err = %v, want ErrClosed", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("Close took %v to unblock the dial, want < 1s", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadPacket did not return after Close during dial")
	}
}

// Fix 2: a server that accepts then instantly drops must be paced, not spun on.
func TestReconnectingPacesAcceptThenDrop(t *testing.T) {
	var dials int64
	dialer := func(ctx context.Context) (io.ReadWriteCloser, error) {
		atomic.AddInt64(&dials, 1)
		c1, c2 := net.Pipe()
		c2.Close() // server end immediately closed => client I/O fails at once
		return c1, nil
	}
	tr := NewReconnectingTransport(ReconnectingConfig{
		Dialer:     dialer,
		MinBackoff: 20 * time.Millisecond,
		MaxBackoff: 40 * time.Millisecond,
	})
	go func() { tr.ReadPacket() }() // loops reconnecting until Close

	time.Sleep(200 * time.Millisecond)
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	n := atomic.LoadInt64(&dials)
	// ~20ms pacing over ~200ms => roughly 10 dials. Without pacing this would be
	// thousands. Allow generous slack but catch a hot spin.
	if n > 50 {
		t.Fatalf("dials = %d in 200ms; accept-then-drop is NOT paced (hot spin)", n)
	}
	if n < 2 {
		t.Fatalf("dials = %d; expected several reconnect attempts", n)
	}
}
