package transport

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/g00dvin/gvpn/core/frame"
)

// ErrClosed is returned by a ReconnectingTransport after Close.
var ErrClosed = errors.New("transport: closed")

const (
	defaultMinBackoff  = 100 * time.Millisecond
	defaultMaxBackoff  = 30 * time.Second
	defaultDialTimeout = 10 * time.Second
)

// ReconnectingConfig configures a ReconnectingTransport.
type ReconnectingConfig struct {
	// Dialer establishes a new connection. Required.
	Dialer Dialer
	// SessionToken, if non-empty, is sent in a SESSION_BIND frame immediately
	// after every (re)connect so the server can rebind an existing session.
	SessionToken []byte
	// MinBackoff/MaxBackoff bound the exponential reconnect backoff.
	MinBackoff time.Duration
	MaxBackoff time.Duration
	// DialTimeout bounds each dial attempt.
	DialTimeout time.Duration
}

// ReconnectingTransport is a PacketTransport that hides connection loss. When
// the underlying connection fails, ReadPacket and WritePacket transparently
// re-dial (with exponential backoff and a fresh SESSION_BIND) and retry; they
// return ErrClosed only after Close. This is the contract WireGuard relies on:
// it observes a stall across a network change, never an EOF.
type ReconnectingTransport struct {
	dial         Dialer
	sessionToken []byte
	minBackoff   time.Duration
	maxBackoff   time.Duration
	dialTimeout  time.Duration

	connMu  sync.Mutex // guards conn, gen, closed
	conn    io.ReadWriteCloser
	gen     uint64
	closed  bool
	closeCh chan struct{}

	dialMu  sync.Mutex // serializes (re)dial attempts
	writeMu sync.Mutex // serializes writes to the current conn
}

// NewReconnectingTransport creates a transport from cfg. It dials lazily: the
// first ReadPacket or WritePacket establishes the connection.
func NewReconnectingTransport(cfg ReconnectingConfig) *ReconnectingTransport {
	t := &ReconnectingTransport{
		dial:         cfg.Dialer,
		sessionToken: cfg.SessionToken,
		minBackoff:   cfg.MinBackoff,
		maxBackoff:   cfg.MaxBackoff,
		dialTimeout:  cfg.DialTimeout,
		closeCh:      make(chan struct{}),
	}
	if t.minBackoff <= 0 {
		t.minBackoff = defaultMinBackoff
	}
	if t.maxBackoff <= 0 {
		t.maxBackoff = defaultMaxBackoff
	}
	if t.dialTimeout <= 0 {
		t.dialTimeout = defaultDialTimeout
	}
	return t
}

func (t *ReconnectingTransport) isClosed() bool {
	t.connMu.Lock()
	defer t.connMu.Unlock()
	return t.closed
}

// ensure returns a usable connection and its generation. If hasBad is true and
// the current generation equals badGen, the current connection is treated as
// dead and a reconnect is forced. ensure blocks (with backoff) until a
// connection is established or the transport is closed.
func (t *ReconnectingTransport) ensure(badGen uint64, hasBad bool) (io.ReadWriteCloser, uint64, error) {
	// Fast path: a good connection already exists.
	t.connMu.Lock()
	if t.closed {
		t.connMu.Unlock()
		return nil, 0, ErrClosed
	}
	if t.conn != nil && !(hasBad && t.gen == badGen) {
		c, g := t.conn, t.gen
		t.connMu.Unlock()
		return c, g, nil
	}
	t.connMu.Unlock()

	// Slow path: serialize dialing so only one goroutine reconnects at a time.
	t.dialMu.Lock()
	defer t.dialMu.Unlock()

	// Re-check: another goroutine may have reconnected while we waited.
	t.connMu.Lock()
	if t.closed {
		t.connMu.Unlock()
		return nil, 0, ErrClosed
	}
	if t.conn != nil && !(hasBad && t.gen == badGen) {
		c, g := t.conn, t.gen
		t.connMu.Unlock()
		return c, g, nil
	}
	old := t.conn
	t.conn = nil
	t.connMu.Unlock()
	if old != nil {
		_ = old.Close()
	}

	backoff := t.minBackoff
	for {
		if t.isClosed() {
			return nil, 0, ErrClosed
		}
		conn, err := t.dialOnce()
		if err == nil {
			t.connMu.Lock()
			if t.closed {
				t.connMu.Unlock()
				_ = conn.Close()
				return nil, 0, ErrClosed
			}
			t.conn = conn
			t.gen++
			g := t.gen
			t.connMu.Unlock()
			return conn, g, nil
		}
		select {
		case <-t.closeCh:
			return nil, 0, ErrClosed
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > t.maxBackoff {
			backoff = t.maxBackoff
		}
	}
}

// dialOnce performs a single dial and sends the SESSION_BIND frame (if any).
func (t *ReconnectingTransport) dialOnce() (io.ReadWriteCloser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), t.dialTimeout)
	defer cancel()
	conn, err := t.dial(ctx)
	if err != nil {
		return nil, err
	}
	if len(t.sessionToken) > 0 {
		if err := frame.WriteFrame(conn, frame.TypeSessionBind, t.sessionToken); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// ReadPacket returns the next DATA-frame payload, transparently reconnecting on
// failure. It returns ErrClosed only after Close.
func (t *ReconnectingTransport) ReadPacket() ([]byte, error) {
	var badGen uint64
	var hasBad bool
	for {
		conn, gen, err := t.ensure(badGen, hasBad)
		if err != nil {
			return nil, err
		}
		typ, payload, rerr := frame.ReadFrame(conn)
		if rerr != nil {
			if t.isClosed() {
				return nil, ErrClosed
			}
			badGen, hasBad = gen, true
			continue
		}
		if typ == frame.TypeData {
			return payload, nil
		}
		// Non-DATA frames (heartbeat, control) are skipped at this layer.
	}
}

// WritePacket sends p as a DATA frame, transparently reconnecting on failure.
func (t *ReconnectingTransport) WritePacket(p []byte) error {
	var badGen uint64
	var hasBad bool
	for {
		conn, gen, err := t.ensure(badGen, hasBad)
		if err != nil {
			return err
		}
		t.writeMu.Lock()
		werr := frame.WriteFrame(conn, frame.TypeData, p)
		t.writeMu.Unlock()
		if werr != nil {
			if t.isClosed() {
				return ErrClosed
			}
			badGen, hasBad = gen, true
			continue
		}
		return nil
	}
}

// Close releases the transport. In-flight and subsequent Read/Write calls
// return ErrClosed.
func (t *ReconnectingTransport) Close() error {
	t.connMu.Lock()
	if t.closed {
		t.connMu.Unlock()
		return nil
	}
	t.closed = true
	close(t.closeCh)
	c := t.conn
	t.conn = nil
	t.connMu.Unlock()
	if c != nil {
		return c.Close()
	}
	return nil
}

var _ PacketTransport = (*ReconnectingTransport)(nil)
