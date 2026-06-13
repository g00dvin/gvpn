// Package transport defines the boundary between the VPN engine and the
// underlying byte stream. WireGuard interacts with the network exclusively
// through PacketTransport (spec §5).
package transport

import (
	"io"
	"sync"

	"github.com/g00dvin/gvpn/core/frame"
)

// PacketTransport is the only interface the WireGuard engine uses to move
// packets. Implementations hide framing, TLS, and (later) reconnection.
type PacketTransport interface {
	// ReadPacket returns the next VPN packet, blocking until one is available.
	ReadPacket() ([]byte, error)
	// WritePacket sends one VPN packet.
	WritePacket([]byte) error
	// Close releases the transport. Pending Read/Write calls return an error.
	Close() error
}

// StreamTransport adapts a framed byte stream (any io.ReadWriteCloser) into a
// PacketTransport. Each VPN packet is carried in a single DATA frame. Non-DATA
// frames are skipped here; higher layers handle them in later plans.
type StreamTransport struct {
	conn io.ReadWriteCloser
	rmu  sync.Mutex
	wmu  sync.Mutex
}

// NewStreamTransport wraps conn.
func NewStreamTransport(conn io.ReadWriteCloser) *StreamTransport {
	return &StreamTransport{conn: conn}
}

// ReadPacket reads frames until a DATA frame arrives and returns its payload.
func (t *StreamTransport) ReadPacket() ([]byte, error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()
	for {
		typ, payload, err := frame.ReadFrame(t.conn)
		if err != nil {
			return nil, err
		}
		if typ == frame.TypeData {
			return payload, nil
		}
	}
}

// WritePacket writes p as a single DATA frame.
func (t *StreamTransport) WritePacket(p []byte) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	return frame.WriteFrame(t.conn, frame.TypeData, p)
}

// Close closes the underlying connection.
func (t *StreamTransport) Close() error {
	return t.conn.Close()
}
