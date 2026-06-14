package session

import (
	"fmt"
	"net"

	"github.com/g00dvin/gvpn/core/frame"
)

// ClientBind runs the client side of the SESSION_BIND exchange, sent as the
// frame right after AUTH. For a brand-new session pass the zero SessionID (the
// token is then ignored); to resume, pass the SessionID and ResumeToken stored
// from a previous bind. It returns the SessionID and ResumeToken the server
// assigned/confirmed, which the client persists for its next reconnect.
func ClientBind(conn net.Conn, sid [16]byte, token [32]byte) (newSID [16]byte, newToken [32]byte, err error) {
	if err = frame.WriteFrame(conn, frame.TypeSessionBind, marshalBind(sid, token)); err != nil {
		return newSID, newToken, fmt.Errorf("session: write SESSION_BIND: %w", err)
	}
	typ, payload, err := frame.ReadFrame(conn)
	if err != nil {
		return newSID, newToken, fmt.Errorf("session: read SESSION_BIND ack: %w", err)
	}
	if typ != frame.TypeSessionBind {
		return newSID, newToken, fmt.Errorf("session: ack frame is type %d, want SESSION_BIND", typ)
	}
	return parseBind(payload)
}
