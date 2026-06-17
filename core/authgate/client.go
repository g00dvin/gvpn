package authgate

import (
	"net"
	"time"

	"github.com/g00dvin/gvpn/core/frame"
)

// WriteAuth sends the in-tunnel AUTH frame as the first frame on conn, using the
// device PSK and ID. The client must call this immediately after each (re)connect
// and GOST TLS handshake, before any DATA frame (design §3, §5).
func WriteAuth(conn net.Conn, psk []byte, deviceID [16]byte) error {
	tok, err := MakeToken(psk, deviceID, time.Now())
	if err != nil {
		return err
	}
	return frame.WriteFrame(conn, frame.TypeAuth, tok)
}

// WriteEnrollAuth sends a KindEnroll AUTH frame as the first frame on conn, using
// the user's enrollment PSK and 16-byte user id. A new device calls this on its
// first connect to bootstrap enrollment (design §7); steady-state connects use
// WriteAuth with the per-device PSK.
func WriteEnrollAuth(conn net.Conn, enrollPSK []byte, userID [16]byte) error {
	tok, err := MakeEnrollToken(enrollPSK, userID, time.Now())
	if err != nil {
		return err
	}
	return frame.WriteFrame(conn, frame.TypeAuth, tok)
}
