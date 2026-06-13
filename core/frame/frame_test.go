package frame

import (
	"bytes"
	"io"
	"strings"
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
	r := strings.NewReader("\x01\x00\x00\x04hi")
	_, _, err := ReadFrame(r)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}
