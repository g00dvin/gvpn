package transport

import (
	"net"
	"testing"
)

// compile-time assertion that StreamTransport implements PacketTransport.
var _ PacketTransport = (*StreamTransport)(nil)

func TestStreamTransportRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	a := NewStreamTransport(c1)
	b := NewStreamTransport(c2)

	go func() {
		if err := a.WritePacket([]byte("hello")); err != nil {
			t.Errorf("WritePacket: %v", err)
		}
	}()

	got, err := b.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("packet = %q, want %q", got, "hello")
	}
}

func TestStreamTransportCloseUnblocksRead(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	a := NewStreamTransport(c1)

	errc := make(chan error, 1)
	go func() {
		_, err := a.ReadPacket()
		errc <- err
	}()

	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-errc; err == nil {
		t.Fatal("ReadPacket returned nil error after Close, want non-nil")
	}
}
