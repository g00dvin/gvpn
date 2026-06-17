package enroll

import (
	"bytes"
	"testing"
)

func TestRequestRoundTrip(t *testing.T) {
	var in Request
	for i := range in.WGPublic {
		in.WGPublic[i] = byte(i)
	}
	out, err := ParseRequest(in.Marshal())
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if out.WGPublic != in.WGPublic {
		t.Fatalf("round trip = %x, want %x", out.WGPublic, in.WGPublic)
	}
}

func TestParseRequestWrongSize(t *testing.T) {
	if _, err := ParseRequest(make([]byte, 31)); err == nil {
		t.Fatal("ParseRequest(31) accepted")
	}
}

func TestResponseRoundTrip(t *testing.T) {
	in := Response{
		DeviceID:  [16]byte{1, 2, 3, 4},
		TunnelIP:  "10.100.0.7",
		DevicePSK: bytes.Repeat([]byte{0xAB}, 32),
	}
	raw, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out, err := ParseResponse(raw)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if out.DeviceID != in.DeviceID || out.TunnelIP != in.TunnelIP || !bytes.Equal(out.DevicePSK, in.DevicePSK) {
		t.Fatalf("round trip = %+v, want %+v", out, in)
	}
}

func TestParseResponseTruncated(t *testing.T) {
	if _, err := ParseResponse(make([]byte, 10)); err == nil {
		t.Fatal("ParseResponse(short) accepted")
	}
	// deviceID + pskLen says 32 but no psk bytes follow.
	bad := append(make([]byte, 16), 32)
	if _, err := ParseResponse(bad); err == nil {
		t.Fatal("ParseResponse(psk truncated) accepted")
	}
}
