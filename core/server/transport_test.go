package server

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// errTransport is a PacketTransport whose reads fail after a signal, for testing
// that notifyTransport fires Done on the first error.
type errTransport struct {
	mu       sync.Mutex
	failRead bool
	closed   bool
}

func (e *errTransport) ReadPacket() ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failRead {
		return nil, errors.New("read failed")
	}
	return []byte("pkt"), nil
}
func (e *errTransport) WritePacket(p []byte) error { return nil }
func (e *errTransport) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	return nil
}

func TestNotifyTransportSignalsOnReadError(t *testing.T) {
	inner := &errTransport{}
	nt := newNotifyTransport(inner)

	// A successful read does not signal.
	if _, err := nt.ReadPacket(); err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	select {
	case <-nt.Done():
		t.Fatal("Done fired after a successful read")
	default:
	}

	// The first failing read signals Done.
	inner.mu.Lock()
	inner.failRead = true
	inner.mu.Unlock()
	if _, err := nt.ReadPacket(); err == nil {
		t.Fatal("expected read error")
	}
	select {
	case <-nt.Done():
	case <-time.After(time.Second):
		t.Fatal("Done did not fire after a read error")
	}
}

func TestNotifyTransportSignalsOnClose(t *testing.T) {
	nt := newNotifyTransport(&errTransport{})
	if err := nt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-nt.Done():
	case <-time.After(time.Second):
		t.Fatal("Done did not fire after Close")
	}
	// Done is idempotent / single-close (calling Close again must not panic).
	if err := nt.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// notifyTransport must satisfy transport.PacketTransport (compile-time check via use).
var _ = net.Conn(nil)
