package enroll

import (
	"fmt"
	"net"

	"github.com/g00dvin/gvpn/core/frame"
)

// Exchange runs the device side of the enrollment exchange on an already-gated
// connection: it sends the WireGuard public key and returns the server's
// Response. The caller manages any read/write deadlines on conn.
func Exchange(conn net.Conn, wgPublic [32]byte) (Response, error) {
	if err := frame.WriteFrame(conn, frame.TypeEnrollRequest, Request{WGPublic: wgPublic}.Marshal()); err != nil {
		return Response{}, err
	}
	typ, payload, err := frame.ReadFrame(conn)
	if err != nil {
		return Response{}, err
	}
	if typ != frame.TypeEnrollResponse {
		return Response{}, fmt.Errorf("enroll: expected response frame, got type %d", typ)
	}
	return ParseResponse(payload)
}

// ReadRequest runs on the server: it reads the device's enrollment Request frame.
func ReadRequest(conn net.Conn) (Request, error) {
	typ, payload, err := frame.ReadFrame(conn)
	if err != nil {
		return Request{}, err
	}
	if typ != frame.TypeEnrollRequest {
		return Request{}, fmt.Errorf("enroll: expected request frame, got type %d", typ)
	}
	return ParseRequest(payload)
}

// WriteResponse runs on the server: it sends the enrollment Response frame.
func WriteResponse(conn net.Conn, resp Response) error {
	b, err := resp.Marshal()
	if err != nil {
		return err
	}
	return frame.WriteFrame(conn, frame.TypeEnrollResponse, b)
}
