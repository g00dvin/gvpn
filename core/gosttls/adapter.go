package gosttls

import (
	"context"
	"io"

	"github.com/g00dvin/gvpn/core/transport"
)

// DialGOSTTLS adapts the GOST TLS client into a transport.Dialer, so the
// reconnecting transport (Plan 2) runs each connection over GOST TLS. The
// returned dialer establishes a fresh GOST TLS connection to addr on every
// call, which is exactly what reconnection needs.
func DialGOSTTLS(network, addr string, cfg Config) transport.Dialer {
	return func(ctx context.Context) (io.ReadWriteCloser, error) {
		conn, err := Dial(ctx, network, addr, cfg)
		if err != nil {
			// Return a true nil interface, not a nil *Conn wrapped in one.
			return nil, err
		}
		return conn, nil
	}
}
