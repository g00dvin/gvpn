package frame

import (
	"bytes"
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
