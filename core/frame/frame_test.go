package frame

import (
	"bytes"
	"io"
	"testing"
)

func TestHeaderMarshalParseRoundTrip(t *testing.T) {
	h := Header{Version: Version1, Type: TypeData, Length: 0x1234}
	b := h.Marshal()
	if len(b) != HeaderSize {
		t.Fatalf("marshal length = %d, want %d", len(b), HeaderSize)
	}
	want := []byte{0x01, 0x00, 0x12, 0x34}
	if !bytes.Equal(b, want) {
		t.Fatalf("marshal = % x, want % x", b, want)
	}
	got, err := ParseHeader(b)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if got != h {
		t.Fatalf("parsed = %+v, want %+v", got, h)
	}
}

func TestParseHeaderShort(t *testing.T) {
	_, err := ParseHeader([]byte{0x01, 0x00})
	if err != ErrShortHeader {
		t.Fatalf("err = %v, want ErrShortHeader", err)
	}
}

func TestWriteFrame(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, TypeData, []byte("hi")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	want := []byte{0x01, 0x00, 0x00, 0x02, 'h', 'i'}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("frame = % x, want % x", buf.Bytes(), want)
	}
}

func TestWriteFrameTooLarge(t *testing.T) {
	var buf bytes.Buffer
	err := WriteFrame(&buf, TypeData, make([]byte, MaxPayloadSize+1))
	if err != ErrPayloadTooLarge {
		t.Fatalf("err = %v, want ErrPayloadTooLarge", err)
	}
}

func TestReadFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, TypeHeartbeat, []byte("ping")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	typ, payload, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if typ != TypeHeartbeat {
		t.Fatalf("type = %d, want %d", typ, TypeHeartbeat)
	}
	if string(payload) != "ping" {
		t.Fatalf("payload = %q, want %q", payload, "ping")
	}
}

func TestReadFrameUnsupportedVersion(t *testing.T) {
	r := bytes.NewReader([]byte{0x09, 0x00, 0x00, 0x00})
	_, _, err := ReadFrame(r)
	if err != ErrUnsupportedVersion {
		t.Fatalf("err = %v, want ErrUnsupportedVersion", err)
	}
}

func TestReadFrameTruncatedPayload(t *testing.T) {
	// Header claims 4 bytes of payload but only 2 are present.
	r := bytes.NewReader([]byte{0x01, 0x00, 0x00, 0x04, 'h', 'i'})
	_, _, err := ReadFrame(r)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestWriteReadEmptyPayload(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, TypeHeartbeat, []byte{}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	typ, payload, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if typ != TypeHeartbeat {
		t.Fatalf("type = %d, want %d", typ, TypeHeartbeat)
	}
	if len(payload) != 0 {
		t.Fatalf("payload len = %d, want 0", len(payload))
	}
}

func TestWriteReadMaxPayload(t *testing.T) {
	in := make([]byte, MaxPayloadSize)
	for i := range in {
		in[i] = byte(i)
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, TypeData, in); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	_, payload, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(payload, in) {
		t.Fatalf("payload mismatch (got len %d, want %d)", len(payload), len(in))
	}
}

func TestReadFrameCleanEOF(t *testing.T) {
	_, _, err := ReadFrame(bytes.NewReader(nil))
	if err != io.EOF {
		t.Fatalf("err = %v, want io.EOF", err)
	}
}
