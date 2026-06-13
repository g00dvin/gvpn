package transport

import (
	"context"
	"io"
	"net"
)

// Dialer establishes a fresh framed connection. The context bounds the dial.
// A later plan wraps the TCP dialer with GOST TLS; the rest of the transport is
// agnostic to what the Dialer returns.
type Dialer func(ctx context.Context) (io.ReadWriteCloser, error)

// DialTCP returns a Dialer that opens plain TCP connections to address
// ("host:port").
func DialTCP(address string) Dialer {
	return func(ctx context.Context) (io.ReadWriteCloser, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", address)
	}
}
