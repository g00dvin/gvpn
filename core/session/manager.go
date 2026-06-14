package session

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"sync"
	"time"
)

// Resume errors. All map to the same outcome on the wire (the server drops the
// connection); they are distinguished only for server-side logging/metrics.
var (
	ErrUnknownSession = errors.New("session: unknown or expired session")
	ErrWrongDevice    = errors.New("session: session belongs to a different device")
	ErrBadResumeToken = errors.New("session: resume token mismatch")
)

// Session is the server-side resume anchor for one client tunnel. The live
// connection is NOT stored here — it is swapped on every reconnect; the session
// holds identity + resume state only (design §6).
type Session struct {
	SessionID   [16]byte
	DeviceID    [16]byte
	ResumeToken [32]byte
	LastSeen    time.Time
}

// Manager is the server-side session registry. Safe for concurrent use.
type Manager struct {
	ttl  time.Duration
	now  func() time.Time
	rand io.Reader
	mu   sync.Mutex
	byID map[[16]byte]*Session
}

// NewManager returns a registry whose sessions expire ttl after their last use.
func NewManager(ttl time.Duration) *Manager {
	return &Manager{
		ttl:  ttl,
		now:  time.Now,
		rand: rand.Reader,
		byID: make(map[[16]byte]*Session),
	}
}

// create mints a brand-new session for deviceID with a random SessionID and
// ResumeToken, stamped now.
func (m *Manager) create(deviceID [16]byte) (*Session, error) {
	var sid [16]byte
	var token [32]byte
	if _, err := io.ReadFull(m.rand, sid[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(m.rand, token[:]); err != nil {
		return nil, err
	}
	s := &Session{SessionID: sid, DeviceID: deviceID, ResumeToken: token, LastSeen: m.now()}
	m.mu.Lock()
	m.byID[sid] = s
	m.mu.Unlock()
	return s, nil
}

// resume rebinds an existing session. It must exist, be unexpired, belong to
// deviceID, and present the matching resume token (constant-time compare). On
// success LastSeen is refreshed.
func (m *Manager) resume(deviceID [16]byte, sid [16]byte, token [32]byte) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[sid]
	if !ok || m.now().Sub(s.LastSeen) > m.ttl {
		if ok {
			delete(m.byID, sid) // opportunistically drop the expired entry
		}
		return nil, ErrUnknownSession
	}
	if s.DeviceID != deviceID {
		return nil, ErrWrongDevice
	}
	if subtle.ConstantTimeCompare(s.ResumeToken[:], token[:]) != 1 {
		return nil, ErrBadResumeToken
	}
	s.LastSeen = m.now()
	return s, nil
}

// Sweep removes expired sessions. A server calls it periodically.
func (m *Manager) Sweep() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for id, s := range m.byID {
		if now.Sub(s.LastSeen) > m.ttl {
			delete(m.byID, id)
		}
	}
}

// Count returns the number of live sessions (tests/metrics).
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byID)
}
