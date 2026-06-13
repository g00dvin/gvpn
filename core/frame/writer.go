package frame

import (
	"encoding/binary"
	"io"
)

// WriteFrame writes a single frame (header + payload) to w in one Write call,
// so concurrent writers (holding an external lock) never interleave a header
// with another frame's payload. It returns ErrPayloadTooLarge if payload
// exceeds MaxPayloadSize. The header is written directly into the output buffer
// to avoid a separate allocation on the per-packet hot path.
func WriteFrame(w io.Writer, t Type, payload []byte) error {
	if len(payload) > MaxPayloadSize {
		return ErrPayloadTooLarge
	}
	buf := make([]byte, HeaderSize, HeaderSize+len(payload))
	buf[0] = Version1
	buf[1] = byte(t)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(payload)))
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}
