package wgengine

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// fakePT is an in-memory PacketTransport for testing the Bind.
type fakePT struct {
	in        chan []byte // ReadPacket source
	out       chan []byte // WritePacket sink
	closeOnce sync.Once
	closed    chan struct{}
}

func newFakePT() *fakePT {
	return &fakePT{in: make(chan []byte, 8), out: make(chan []byte, 8), closed: make(chan struct{})}
}
func (f *fakePT) ReadPacket() ([]byte, error) {
	select {
	case p := <-f.in:
		return p, nil
	case <-f.closed:
		return nil, net.ErrClosed
	}
}
func (f *fakePT) WritePacket(p []byte) error {
	select {
	case f.out <- p:
		return nil
	case <-f.closed:
		return net.ErrClosed
	}
}
func (f *fakePT) Close() error { f.closeOnce.Do(func() { close(f.closed) }); return nil }

func TestBindSendCopiesAndForwards(t *testing.T) {
	pt := newFakePT()
	b := NewBind(pt)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	pkt := []byte("wireguard-packet")
	if err := b.Send([][]byte{pkt}, peerEndpoint{}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// Mutating the caller's buffer after Send must not affect what was written.
	for i := range pkt {
		pkt[i] = 0
	}
	select {
	case got := <-pt.out:
		if !bytes.Equal(got, []byte("wireguard-packet")) {
			t.Fatalf("forwarded %q, want %q (Send must copy)", got, "wireguard-packet")
		}
	case <-time.After(time.Second):
		t.Fatal("nothing written to transport")
	}
}

func TestBindReceiveDeliversPacket(t *testing.T) {
	pt := newFakePT()
	b := NewBind(pt)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	pt.in <- []byte("incoming")
	packets := [][]byte{make([]byte, 1500)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := fns[0](packets, sizes, eps)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if n != 1 || string(packets[0][:sizes[0]]) != "incoming" {
		t.Fatalf("receive n=%d data=%q", n, packets[0][:sizes[0]])
	}
}

func TestBindCloseUnblocksReceive(t *testing.T) {
	pt := newFakePT()
	b := NewBind(pt)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	errc := make(chan error, 1)
	go func() {
		packets := [][]byte{make([]byte, 1500)}
		_, e := fns[0](packets, make([]int, 1), make([]conn.Endpoint, 1))
		errc <- e
	}()
	time.Sleep(20 * time.Millisecond) // let the receive func block
	b.Close()
	select {
	case e := <-errc:
		if !errors.Is(e, net.ErrClosed) {
			t.Fatalf("receive after Close = %v, want net.ErrClosed", e)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock the receive func")
	}
}

func TestBindReopenAfterClose(t *testing.T) {
	pt := newFakePT()
	b := NewBind(pt)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open 1: %v", err)
	}
	b.Close()
	fns, _, err := b.Open(0) // wireguard may Close+Open during (re)configuration
	if err != nil {
		t.Fatalf("Open 2: %v", err)
	}
	pt.in <- []byte("after-reopen")
	n, err := fns[0]([][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1))
	if err != nil || n != 1 {
		t.Fatalf("receive after reopen: n=%d err=%v", n, err)
	}
}

func TestBindStaticContract(t *testing.T) {
	b := NewBind(newFakePT())
	if b.BatchSize() != 1 {
		t.Fatalf("BatchSize = %d, want 1", b.BatchSize())
	}
	if err := b.SetMark(0); err != nil {
		t.Fatalf("SetMark: %v", err)
	}
	if ep, err := b.ParseEndpoint("anything"); err != nil || ep == nil {
		t.Fatalf("ParseEndpoint: ep=%v err=%v", ep, err)
	}
}
