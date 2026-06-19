package wgengine

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/g00dvin/gvpn/core/transport"
	"golang.zx2c4.com/wireguard/conn"
)

// muxEndpoint identifies the connection a packet arrived on. wireguard-go treats
// it as the peer's endpoint, so returning it from the receive func lets the
// device learn — and, on reconnect, re-point — which connection reaches a peer.
type muxEndpoint struct{ id uint64 }

func (muxEndpoint) ClearSrc()             {}
func (muxEndpoint) SrcToString() string   { return "" }
func (e muxEndpoint) DstToString() string { return fmt.Sprintf("gvpn-mux:%d", e.id) }
func (e muxEndpoint) DstToBytes() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, e.id)
	return b
}
func (muxEndpoint) DstIP() netip.Addr { return netip.Addr{} }
func (muxEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

// muxItem is one received packet tagged with its origin connection id.
type muxItem struct {
	pkt []byte
	ep  muxEndpoint
}

// muxConn tracks one registered connection's transport and reader stop signal.
type muxConn struct {
	pt   transport.PacketTransport
	stop chan struct{}
	once sync.Once
}

// MuxBind is a conn.Bind for ONE wireguard-go device fed by MANY connections.
// Each registered connection runs a reader goroutine that fans frames into a
// shared receive channel tagged with the connection id; Send routes an outbound
// packet back to the connection named by its endpoint id.
type MuxBind struct {
	mu   sync.Mutex
	open bool
	done chan struct{} // current Open generation; closed by Close
	recv chan muxItem

	connsMu sync.RWMutex
	conns   map[uint64]*muxConn

	wg       sync.WaitGroup
	dead     chan struct{} // closed by Shutdown; releases readers blocked on recv
	deadOnce sync.Once
}

var _ conn.Bind = (*MuxBind)(nil)

// NewMuxBind builds an empty MuxBind. Register connections after Open.
func NewMuxBind() *MuxBind {
	return &MuxBind{
		recv:  make(chan muxItem, conn.IdealBatchSize),
		conns: make(map[uint64]*muxConn),
		dead:  make(chan struct{}),
	}
}

// Open returns a single receive function draining the shared channel. actualPort
// is 0 (the transport is not UDP). wireguard may Close+Open during reconfig; each
// Open starts a fresh receive generation.
func (b *MuxBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.done = make(chan struct{})
	b.open = true
	done := b.done

	fn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case it := <-b.recv:
			sizes[0] = copy(packets[0], it.pkt)
			eps[0] = it.ep
			return 1, nil
		case <-done:
			return 0, net.ErrClosed
		}
	}
	return []conn.ReceiveFunc{fn}, 0, nil
}

// Close ends the current receive generation. It does not stop readers or touch
// the connections.
func (b *MuxBind) Close() error {
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

// Register adds connection id backed by pt and starts its reader goroutine. The
// reader exits when pt errors (owner closed the conn), when Deregister(id) is
// called, or when Shutdown closes the bind.
//
// Callers must use a unique id per live connection. Re-registering an id that is
// still live supersedes the old connection: its reader is signalled to stop and
// its now-orphaned transport is closed (which also unblocks a reader parked in
// ReadPacket), so the old reader is never leaked.
func (b *MuxBind) Register(id uint64, pt transport.PacketTransport) {
	mc := &muxConn{pt: pt, stop: make(chan struct{})}
	b.connsMu.Lock()
	prev := b.conns[id]
	b.conns[id] = mc
	b.connsMu.Unlock()
	if prev != nil {
		prev.once.Do(func() { close(prev.stop) })
		prev.pt.Close()
	}

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for {
			p, err := pt.ReadPacket()
			if err != nil {
				return
			}
			select {
			case b.recv <- muxItem{pkt: p, ep: muxEndpoint{id: id}}:
			case <-mc.stop:
				return
			case <-b.dead:
				return
			}
		}
	}()
}

// Deregister removes connection id from the routing table and signals its reader
// to stop. A reader parked in ReadPacket exits when the owner closes the conn.
func (b *MuxBind) Deregister(id uint64) {
	b.connsMu.Lock()
	mc, ok := b.conns[id]
	if ok {
		delete(b.conns, id)
	}
	b.connsMu.Unlock()
	if ok {
		mc.once.Do(func() { close(mc.stop) })
	}
}

// Send routes each packet to the transport named by ep.id. wireguard reuses bufs
// after Send, so each packet is copied first. An unknown id or non-mux endpoint
// is dropped (the peer's endpoint is stale until it reconnects).
func (b *MuxBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	open := b.open
	b.mu.Unlock()
	if !open {
		return net.ErrClosed
	}
	me, ok := ep.(muxEndpoint)
	if !ok {
		return nil
	}
	b.connsMu.RLock()
	mc, ok := b.conns[me.id]
	b.connsMu.RUnlock()
	if !ok {
		return nil
	}
	for _, buf := range bufs {
		if len(buf) == 0 {
			continue
		}
		pkt := make([]byte, len(buf))
		copy(pkt, buf)
		if err := mc.pt.WritePacket(pkt); err != nil {
			return err
		}
	}
	return nil
}

// Shutdown releases all reader goroutines and waits for them to exit. It closes
// every still-registered transport to unblock readers parked in ReadPacket, so
// it never hangs even if the owner has not closed the conns. Called by
// MuxEngine.Close after the device is closed.
func (b *MuxBind) Shutdown() {
	b.deadOnce.Do(func() { close(b.dead) })
	b.connsMu.Lock()
	for id, mc := range b.conns {
		mc.pt.Close()
		delete(b.conns, id)
	}
	b.connsMu.Unlock()
	b.wg.Wait()
}

// ParseEndpoint returns a zero-id mux endpoint regardless of s. The server never
// configures a static endpoint= (it does not initiate), so this is unused in
// practice; a zero id is unknown to Send and harmlessly drops.
func (b *MuxBind) ParseEndpoint(s string) (conn.Endpoint, error) { return muxEndpoint{}, nil }

// SetMark is a no-op: there is no OS socket to mark.
func (b *MuxBind) SetMark(mark uint32) error { return nil }

// BatchSize is 1: a framed stream delivers one packet per read.
func (b *MuxBind) BatchSize() int { return 1 }
