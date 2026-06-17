package enroll

import (
	"bytes"
	"fmt"
	"net"
	"testing"
)

func TestExchangeRoundTrip(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	want := Response{DeviceID: [16]byte{9, 8, 7}, TunnelIP: "10.100.0.5", DevicePSK: bytes.Repeat([]byte{1}, 32)}
	var wgPub [32]byte
	for i := range wgPub {
		wgPub[i] = byte(255 - i)
	}

	errc := make(chan error, 1)
	go func() {
		req, err := ReadRequest(s)
		if err != nil {
			errc <- err
			return
		}
		if req.WGPublic != wgPub {
			errc <- fmt.Errorf("server got wg %x, want %x", req.WGPublic, wgPub)
			return
		}
		errc <- WriteResponse(s, want)
	}()

	got, err := Exchange(c, wgPub)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server: %v", err)
	}
	if got.DeviceID != want.DeviceID || got.TunnelIP != want.TunnelIP || !bytes.Equal(got.DevicePSK, want.DevicePSK) {
		t.Fatalf("Exchange = %+v, want %+v", got, want)
	}
}

func TestReadRequestRejectsWrongFrameType(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() { WriteResponse(c, Response{DeviceID: [16]byte{1}, DevicePSK: []byte("x")}) }() // wrong type for a request
	if _, err := ReadRequest(s); err == nil {
		t.Fatal("ReadRequest accepted a non-request frame")
	}
}
