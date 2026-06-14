package authgate

import (
	"io"
	"net"
	"time"

	"github.com/g00dvin/gvpn/core/frame"
)

// Default gate timings.
const (
	defaultWindow      = 30 * time.Second
	defaultReadTimeout = 10 * time.Second
)

// Result is the outcome of Gate.Handle.
type Result struct {
	// Authenticated is true when the first frame was a valid, fresh AUTH token.
	Authenticated bool
	// DeviceID is the verified device; set only when Authenticated.
	DeviceID [16]byte
	// Conn is the connection positioned immediately after the AUTH frame, ready
	// for the VPN data path. Set only when Authenticated; otherwise the gate has
	// already handed the connection to the decoy (or closed it) and Conn is nil.
	Conn net.Conn
}

// Gate is the server-side in-tunnel authentication gate. It inspects the first
// frame of an already-TLS-terminated connection: a valid AUTH token switches the
// connection to the VPN data path; anything else is reverse-proxied to the decoy
// (design §3).
type Gate struct {
	store       DeviceStore
	decoy       Decoy
	replay      *ReplayCache
	window      time.Duration
	readTimeout time.Duration
	now         func() time.Time
}

// NewGate builds a Gate. store resolves device PSKs; decoy receives
// unauthenticated connections (nil => they are simply closed). Defaults: 30s
// token window, 10s first-frame read timeout, replay TTL = 2*window.
func NewGate(store DeviceStore, decoy Decoy) *Gate {
	return &Gate{
		store:       store,
		decoy:       decoy,
		replay:      NewReplayCache(2 * defaultWindow),
		window:      defaultWindow,
		readTimeout: defaultReadTimeout,
		now:         time.Now,
	}
}

// Handle inspects conn's first frame and decides VPN-vs-decoy. On the
// authenticated path it returns Result{Authenticated:true, Conn:conn} (caller
// owns conn). On the decoy path it proxies/closes conn and returns
// Result{Authenticated:false}; any decoy error is returned for logging but conn
// is consumed either way.
func (g *Gate) Handle(conn net.Conn) (Result, error) {
	_ = conn.SetReadDeadline(time.Now().Add(g.readTimeout))
	rec := &recordingReader{r: conn}

	hdr := make([]byte, frame.HeaderSize)
	if _, err := io.ReadFull(rec, hdr); err != nil {
		return g.toDecoy(conn, rec.buf)
	}
	h, err := frame.ParseHeader(hdr)
	// Reject on the header alone before reading any payload: strict version/type
	// and an exact AUTH length keep a prober from steering us into a large read.
	if err != nil || h.Version != frame.Version1 || h.Type != frame.TypeAuth || int(h.Length) != TokenSize {
		return g.toDecoy(conn, rec.buf)
	}
	payload := make([]byte, TokenSize)
	if _, err := io.ReadFull(rec, payload); err != nil {
		return g.toDecoy(conn, rec.buf)
	}
	tok, err := ParseToken(payload)
	if err != nil {
		return g.toDecoy(conn, rec.buf)
	}
	psk, ok := g.store.Lookup(tok.DeviceID)
	if !ok {
		return g.toDecoy(conn, rec.buf)
	}
	if err := tok.Verify(psk, g.now(), g.window); err != nil {
		return g.toDecoy(conn, rec.buf)
	}
	if g.replay.Seen(tok.Nonce) {
		return g.toDecoy(conn, rec.buf)
	}

	_ = conn.SetReadDeadline(time.Time{}) // hand a clean conn to the data path
	return Result{Authenticated: true, DeviceID: tok.DeviceID, Conn: conn}, nil
}

func (g *Gate) toDecoy(conn net.Conn, prefix []byte) (Result, error) {
	_ = conn.SetReadDeadline(time.Time{})
	if g.decoy == nil {
		conn.Close()
		return Result{Authenticated: false}, nil
	}
	err := g.decoy.Handle(conn, prefix)
	return Result{Authenticated: false}, err
}

// recordingReader records every byte read so the gate can replay the consumed
// prefix to the decoy when authentication fails.
type recordingReader struct {
	r   io.Reader
	buf []byte
}

func (rr *recordingReader) Read(p []byte) (int, error) {
	n, err := rr.r.Read(p)
	if n > 0 {
		rr.buf = append(rr.buf, p[:n]...)
	}
	return n, err
}
