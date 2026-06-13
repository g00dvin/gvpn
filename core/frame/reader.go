package frame

import "io"

// ReadFrame reads one frame from r and returns its type and payload. It uses
// io.ReadFull, so a truncated stream yields io.ErrUnexpectedEOF and a clean EOF
// before any byte yields io.EOF. The payload length is bounded by the uint16
// header field (<= MaxPayloadSize), so allocation is always safe.
func ReadFrame(r io.Reader) (Type, []byte, error) {
	hb := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, hb); err != nil {
		return 0, nil, err
	}
	h, err := ParseHeader(hb)
	if err != nil {
		return 0, nil, err
	}
	if h.Version != Version1 {
		return 0, nil, ErrUnsupportedVersion
	}
	payload := make([]byte, h.Length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return h.Type, payload, nil
}
