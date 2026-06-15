// Package wgengine embeds wireguard-go and drives its outside traffic over a
// connection-oriented transport.PacketTransport (GOST TLS + framing) instead of
// UDP. Pure Go; the TUN device is supplied by the caller (real TUN in
// production, tun/netstack in tests).
package wgengine

import (
	"net"
	"net/netip"
	"sync"

	"github.com/g00dvin/gvpn/core/transport"
	"golang.zx2c4.com/wireguard/conn"
)

// peerEndpoint is the single fixed endpoint for our point-to-point bind. The
// transport already targets exactly one peer (one connection), so endpoint
// addressing is meaningless; we return this for every Send/Receive.
type peerEndpoint struct{}

func (peerEndpoint) ClearSrc()           {}
func (peerEndpoint) SrcToString() string { return "" }
func (peerEndpoint) DstToString() string { return "gvpn-transport" }
func (peerEndpoint) DstToBytes() []byte  { return []byte("gvpn") }
func (peerEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (peerEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// Bind adapts a transport.PacketTransport to wireguard-go's conn.Bind.
//
// Lifecycle: one Bind wraps one transport for the life of one device. Open may
// be called more than once (wireguard calls Close+Open when reconfiguring the
// bind); each Open starts a fresh receive generation. Bind.Close stops the
// current receive funcs (they return net.ErrClosed) but does NOT close the
// transport. The owner (Engine) calls stopReader() + transport.Close() to end
// the background reader.
type Bind struct {
	pt transport.PacketTransport

	mu   sync.Mutex
	open bool
	done chan struct{} // closed by Close; replaced on each Open

	recv     chan []byte // background reader -> receive funcs
	readerOn sync.Once
	dead     chan struct{} // closed by stopReader to release a blocked reader
	deadOnce sync.Once

	sendMu sync.Mutex // serializes WritePacket
}

var _ conn.Bind = (*Bind)(nil)

// NewBind wraps pt as a conn.Bind.
func NewBind(pt transport.PacketTransport) *Bind {
	return &Bind{
		pt:   pt,
		recv: make(chan []byte, conn.IdealBatchSize),
		dead: make(chan struct{}),
	}
}

// Open returns a single receive function backed by the transport. actualPort is
// 0 (the transport is not UDP).
func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.done = make(chan struct{})
	b.open = true
	done := b.done
	b.startReader()

	fn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case p, ok := <-b.recv:
			if !ok {
				return 0, net.ErrClosed
			}
			sizes[0] = copy(packets[0], p)
			eps[0] = peerEndpoint{}
			return 1, nil
		case <-done:
			return 0, net.ErrClosed
		}
	}
	return []conn.ReceiveFunc{fn}, 0, nil
}

// startReader launches (once) the goroutine that turns the blocking
// transport.ReadPacket into a channel. It exits when the transport errors (the
// Engine closed it) or stopReader releases it.
func (b *Bind) startReader() {
	b.readerOn.Do(func() {
		go func() {
			for {
				p, err := b.pt.ReadPacket()
				if err != nil {
					close(b.recv)
					return
				}
				select {
				case b.recv <- p:
				case <-b.dead:
					return
				}
			}
		}()
	})
}

// Close ends the current receive generation. It does not touch the transport.
func (b *Bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.open = false
	if b.done != nil {
		select {
		case <-b.done:
		default:
			close(b.done)
		}
	}
	return nil
}

// stopReader releases a reader blocked on delivering to recv. The Engine calls
// it (then transport.Close) during shutdown.
func (b *Bind) stopReader() { b.deadOnce.Do(func() { close(b.dead) }) }

// Send writes each packet to the transport. wireguard reuses bufs after Send
// returns, so each packet is copied first. Writes are serialized.
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	open := b.open
	b.mu.Unlock()
	if !open {
		return net.ErrClosed
	}
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	for _, buf := range bufs {
		if len(buf) == 0 {
			continue
		}
		pkt := make([]byte, len(buf))
		copy(pkt, buf)
		if err := b.pt.WritePacket(pkt); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint returns the fixed peer endpoint regardless of s.
func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) { return peerEndpoint{}, nil }

// SetMark is a no-op: there is no OS socket to mark.
func (b *Bind) SetMark(mark uint32) error { return nil }

// BatchSize is 1: a framed stream delivers one packet per read.
func (b *Bind) BatchSize() int { return 1 }
