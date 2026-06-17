// Package enroll defines the gvpn dynamic-enrollment exchange that runs over the
// framed, GOST-TLS-terminated connection immediately after the AUTH gate admits
// a KindEnroll connection and before the WireGuard data path: the device sends
// its fresh WireGuard public key (Request) and the server replies with the
// allocated device id, tunnel IP, and per-device PSK (Response). Pure Go, no cgo.
package enroll

import (
	"errors"
	"fmt"
)

// Request is the device->server enrollment message: the device's freshly
// generated WireGuard public key.
type Request struct {
	WGPublic [32]byte
}

// Marshal serializes the request as the raw 32-byte key.
func (r Request) Marshal() []byte {
	b := make([]byte, 32)
	copy(b, r.WGPublic[:])
	return b
}

// ParseRequest deserializes a Request.
func ParseRequest(b []byte) (Request, error) {
	if len(b) != 32 {
		return Request{}, fmt.Errorf("enroll: request is %d bytes, want 32", len(b))
	}
	var r Request
	copy(r.WGPublic[:], b)
	return r, nil
}

// Response is the server->device enrollment reply.
type Response struct {
	DeviceID  [16]byte
	TunnelIP  string
	DevicePSK []byte
}

// Marshal serializes the response as deviceID(16) || pskLen(1) || psk || tunnelIP.
func (r Response) Marshal() ([]byte, error) {
	if len(r.DevicePSK) > 255 {
		return nil, errors.New("enroll: device psk too long")
	}
	b := make([]byte, 0, 16+1+len(r.DevicePSK)+len(r.TunnelIP))
	b = append(b, r.DeviceID[:]...)
	b = append(b, byte(len(r.DevicePSK)))
	b = append(b, r.DevicePSK...)
	b = append(b, r.TunnelIP...)
	return b, nil
}

// ParseResponse deserializes a Response.
func ParseResponse(b []byte) (Response, error) {
	if len(b) < 17 {
		return Response{}, errors.New("enroll: response too short")
	}
	var r Response
	copy(r.DeviceID[:], b[:16])
	n := int(b[16])
	if len(b) < 17+n {
		return Response{}, errors.New("enroll: response psk truncated")
	}
	r.DevicePSK = append([]byte(nil), b[17:17+n]...)
	r.TunnelIP = string(b[17+n:])
	return r, nil
}
