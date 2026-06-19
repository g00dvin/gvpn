package wgengine

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// drainOne pulls a single packet from the bind's receive func, returning the
// payload and the endpoint id it was tagged with.
func drainOne(t *testing.T, fn conn.ReceiveFunc) ([]byte, uint64) {
	t.Helper()
	packets := [][]byte{make([]byte, 1500)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := fn(packets, sizes, eps)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if n != 1 {
		t.Fatalf("receive n = %d, want 1", n)
	}
	me, ok := eps[0].(muxEndpoint)
	if !ok {
		t.Fatalf("endpoint type = %T, want muxEndpoint", eps[0])
	}
	return append([]byte(nil), packets[0][:sizes[0]]...), me.id
}

func TestMuxBindFansInTaggedByConn(t *testing.T) {
	b := NewMuxBind()
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	pt1, pt2 := newFakePT(), newFakePT()
	b.Register(1, pt1)
	b.Register(2, pt2)

	pt1.in <- []byte("from-conn-1")
	pkt, id := drainOne(t, fns[0])
	if string(pkt) != "from-conn-1" || id != 1 {
		t.Fatalf("got (%q,%d), want (from-conn-1,1)", pkt, id)
	}
	pt2.in <- []byte("from-conn-2")
	pkt, id = drainOne(t, fns[0])
	if string(pkt) != "from-conn-2" || id != 2 {
		t.Fatalf("got (%q,%d), want (from-conn-2,2)", pkt, id)
	}
}

func TestMuxBindSendRoutesByEndpointID(t *testing.T) {
	b := NewMuxBind()
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	pt1, pt2 := newFakePT(), newFakePT()
	b.Register(1, pt1)
	b.Register(2, pt2)

	if err := b.Send([][]byte{[]byte("to-2")}, muxEndpoint{id: 2}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case got := <-pt2.out:
		if !bytes.Equal(got, []byte("to-2")) {
			t.Fatalf("conn 2 got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("nothing written to conn 2")
	}
	select {
	case stray := <-pt1.out:
		t.Fatalf("conn 1 unexpectedly received %q", stray)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestMuxBindSendUnknownEndpointDropped(t *testing.T) {
	b := NewMuxBind()
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()
	// No conn registered for id 99: Send must not error (peer is mid-reconnect).
	if err := b.Send([][]byte{[]byte("x")}, muxEndpoint{id: 99}); err != nil {
		t.Fatalf("Send to unknown id = %v, want nil (dropped)", err)
	}
}

func TestMuxBindSendCopies(t *testing.T) {
	b := NewMuxBind()
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()
	pt := newFakePT()
	b.Register(1, pt)
	buf := []byte("mutate-me")
	if err := b.Send([][]byte{buf}, muxEndpoint{id: 1}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	for i := range buf {
		buf[i] = 0
	}
	select {
	case got := <-pt.out:
		if string(got) != "mutate-me" {
			t.Fatalf("Send did not copy: got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("nothing written")
	}
}

func TestMuxBindDeregisterStopsRouting(t *testing.T) {
	b := NewMuxBind()
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()
	pt := newFakePT()
	b.Register(1, pt)
	b.Deregister(1)
	// After Deregister, the id is unknown, so Send drops (no error).
	if err := b.Send([][]byte{[]byte("x")}, muxEndpoint{id: 1}); err != nil {
		t.Fatalf("Send after Deregister = %v, want nil", err)
	}
	pt.Close()
}

func TestMuxBindCloseUnblocksReceive(t *testing.T) {
	b := NewMuxBind()
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	errc := make(chan error, 1)
	go func() {
		_, e := fns[0]([][]byte{make([]byte, 1500)}, make([]int, 1), make([]conn.Endpoint, 1))
		errc <- e
	}()
	time.Sleep(20 * time.Millisecond)
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

func TestMuxBindShutdownReleasesReaders(t *testing.T) {
	b := NewMuxBind()
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	pt := newFakePT()
	b.Register(1, pt) // reader will park in ReadPacket (no input)
	b.Close()
	done := make(chan struct{})
	go func() { b.Shutdown(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return (reader leak)")
	}
}

func TestMuxBindReRegisterSameIDStopsOldReaderAndRoutesToNew(t *testing.T) {
	b := NewMuxBind()
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	old := newFakePT()
	b.Register(1, old) // reader parks in ReadPacket (no input)
	newPT := newFakePT()
	b.Register(1, newPT) // re-register the same live id

	// Send for id 1 must reach the NEW transport, not the old one.
	if err := b.Send([][]byte{[]byte("to-new")}, muxEndpoint{id: 1}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case got := <-newPT.out:
		if string(got) != "to-new" {
			t.Fatalf("new conn got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("nothing written to the re-registered conn")
	}

	// The old reader must not be orphaned: Shutdown (which closes old too) returns.
	b.Close()
	done := make(chan struct{})
	go func() { b.Shutdown(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return (old reader orphaned)")
	}
}

func TestMuxBindStaticContract(t *testing.T) {
	b := NewMuxBind()
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
