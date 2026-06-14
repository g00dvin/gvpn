// Package session implements the gvpn server-side session registry and the
// SESSION_BIND reconnect/resume exchange. After the auth gate verifies a
// device, a client binds (new) or rebinds (resume) its server session so VPN
// state survives TCP/IP changes. Pure Go, no cgo.
package session

import "errors"

// SESSION_BIND payload layout: SessionID(16) || ResumeToken(32) = 48 bytes,
// fixed. A fixed size keeps parsing allocation-free and lets the reader bound
// the frame strictly.
const (
	sessionIDSize   = 16
	resumeTokenSize = 32
	bindPayloadSize = sessionIDSize + resumeTokenSize // 48
)

// ErrBindSize is returned when a SESSION_BIND payload is not exactly
// bindPayloadSize bytes.
var ErrBindSize = errors.New("session: wrong SESSION_BIND payload size")

// zeroSessionID is the sentinel a client sends to request a brand-new session.
// A randomly minted SessionID is never all-zero in practice.
var zeroSessionID [sessionIDSize]byte

// marshalBind serializes a SESSION_BIND payload.
func marshalBind(sid [sessionIDSize]byte, token [resumeTokenSize]byte) []byte {
	b := make([]byte, bindPayloadSize)
	copy(b[:sessionIDSize], sid[:])
	copy(b[sessionIDSize:], token[:])
	return b
}

// parseBind deserializes a SESSION_BIND payload.
func parseBind(b []byte) (sid [sessionIDSize]byte, token [resumeTokenSize]byte, err error) {
	if len(b) != bindPayloadSize {
		return sid, token, ErrBindSize
	}
	copy(sid[:], b[:sessionIDSize])
	copy(token[:], b[sessionIDSize:])
	return sid, token, nil
}
