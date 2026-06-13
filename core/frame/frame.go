// Package frame implements the gvpn transport frame protocol: a versioned,
// typed, length-prefixed codec carrying one payload (e.g. a WireGuard packet)
// per frame over any byte stream.
//
// Wire format (network byte order):
//
//	uint8  version   protocol version (starts at 1)
//	uint8  type      frame Type
//	uint16 length    payload length, 0..MaxPayloadSize
//	[length]byte     payload
package frame

import (
	"encoding/binary"
	"errors"
)

// Version1 is the initial protocol version.
const Version1 uint8 = 1

// HeaderSize is the fixed size of a frame header in bytes.
const HeaderSize = 4

// MaxPayloadSize is the largest payload a single frame may carry. It equals the
// maximum value of the uint16 length field, so the field type is itself the
// overflow guard: a frame can never request more than 64 KiB of allocation.
const MaxPayloadSize = 65535

// Type identifies what a frame carries.
type Type uint8

const (
	// TypeData carries a WireGuard packet.
	TypeData Type = 0
	// TypeAuth carries the in-tunnel authentication token (first frame).
	TypeAuth Type = 1
	// TypeHeartbeat is a transport-layer keepalive.
	TypeHeartbeat Type = 2
	// TypeSessionBind carries a reconnect/resume token.
	TypeSessionBind Type = 3
	// TypeControl is reserved for future orchestrator control messages.
	TypeControl Type = 4
)

// Header is the fixed-size frame header.
type Header struct {
	Version uint8
	Type    Type
	Length  uint16
}

// Errors returned by the frame codec.
var (
	// ErrShortHeader is returned by ParseHeader when given fewer than HeaderSize
	// bytes. ReadFrame never returns it, because it always reads a full header first.
	ErrShortHeader        = errors.New("frame: header too short")
	ErrPayloadTooLarge    = errors.New("frame: payload exceeds max size")
	ErrUnsupportedVersion = errors.New("frame: unsupported version")
)

// Marshal serializes the header into a HeaderSize-byte slice.
func (h Header) Marshal() []byte {
	b := make([]byte, HeaderSize)
	b[0] = h.Version
	b[1] = byte(h.Type)
	binary.BigEndian.PutUint16(b[2:4], h.Length)
	return b
}

// ParseHeader deserializes a header from b, which must be at least HeaderSize.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, ErrShortHeader
	}
	return Header{
		Version: b[0],
		Type:    Type(b[1]),
		Length:  binary.BigEndian.Uint16(b[2:4]),
	}, nil
}
