package frame

import "io"

// WriteFrame writes a single frame (header + payload) to w. It returns
// ErrPayloadTooLarge if payload exceeds MaxPayloadSize. The header and payload
// are written in one Write call so concurrent writers (holding an external
// lock) never interleave a header with another frame's payload.
func WriteFrame(w io.Writer, t Type, payload []byte) error {
	if len(payload) > MaxPayloadSize {
		return ErrPayloadTooLarge
	}
	h := Header{Version: Version1, Type: t, Length: uint16(len(payload))}
	buf := make([]byte, 0, HeaderSize+len(payload))
	buf = append(buf, h.Marshal()...)
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}
