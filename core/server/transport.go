// Package server assembles the gvpn server pipeline: it accepts connections,
// authenticates them in-tunnel, binds sessions, and runs a per-client WireGuard
// engine over the framed transport. It is transport-agnostic — production
// supplies a GOST-TLS listener and a real TUN; tests use plain TCP and netstack.
// Pure Go, no cgo.
package server

import (
	"sync"

	"github.com/g00dvin/gvpn/core/transport"
)

// notifyTransport wraps a PacketTransport and closes Done() the first time a
// read or write returns an error (or Close is called), so the server can tear
// down the client's WireGuard engine when the connection dies.
type notifyTransport struct {
	inner transport.PacketTransport
	once  sync.Once
	done  chan struct{}
}

var _ transport.PacketTransport = (*notifyTransport)(nil)

func newNotifyTransport(inner transport.PacketTransport) *notifyTransport {
	return &notifyTransport{inner: inner, done: make(chan struct{})}
}

// Done is closed once the connection has failed or been closed.
func (t *notifyTransport) Done() <-chan struct{} { return t.done }

func (t *notifyTransport) signal() { t.once.Do(func() { close(t.done) }) }

func (t *notifyTransport) ReadPacket() ([]byte, error) {
	p, err := t.inner.ReadPacket()
	if err != nil {
		t.signal()
	}
	return p, err
}

func (t *notifyTransport) WritePacket(p []byte) error {
	err := t.inner.WritePacket(p)
	if err != nil {
		t.signal()
	}
	return err
}

func (t *notifyTransport) Close() error {
	t.signal()
	return t.inner.Close()
}
