package session

import (
	"fmt"
	"net"

	"github.com/g00dvin/gvpn/core/frame"
)

// Bind runs the server side of the SESSION_BIND exchange on an
// already-authenticated connection. deviceID is the device the auth gate
// verified. It reads the client's SESSION_BIND frame:
//   - zero SessionID -> mint a new session;
//   - non-zero       -> resume the existing session (must belong to deviceID and
//     present the matching resume token).
// It then writes back a SESSION_BIND frame with the assigned/confirmed
// SessionID and ResumeToken and returns the bound session. On any failure it
// returns an error and writes nothing (the caller drops the connection),
// keeping every failure indistinguishable to the peer.
func (m *Manager) Bind(deviceID [16]byte, conn net.Conn) (*Session, error) {
	typ, payload, err := frame.ReadFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("session: read SESSION_BIND: %w", err)
	}
	if typ != frame.TypeSessionBind {
		return nil, fmt.Errorf("session: first post-auth frame is type %d, want SESSION_BIND", typ)
	}
	sid, token, err := parseBind(payload)
	if err != nil {
		return nil, err
	}

	var s *Session
	if sid == zeroSessionID {
		s, err = m.create(deviceID)
	} else {
		s, err = m.resume(deviceID, sid, token)
	}
	if err != nil {
		return nil, err
	}

	if err := frame.WriteFrame(conn, frame.TypeSessionBind, marshalBind(s.SessionID, s.ResumeToken)); err != nil {
		return nil, fmt.Errorf("session: write SESSION_BIND ack: %w", err)
	}
	return s, nil
}
