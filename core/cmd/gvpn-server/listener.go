package main

import (
	"net"

	"github.com/g00dvin/gvpn/core/gosttls"
)

// gostNetListener adapts *gosttls.Listener (whose Accept returns *gosttls.Conn,
// itself a net.Conn) to the net.Listener interface that server.Serve consumes.
// Close and Addr are promoted from the embedded listener.
type gostNetListener struct {
	*gosttls.Listener
}

// Accept returns the next GOST TLS connection as a net.Conn.
func (l gostNetListener) Accept() (net.Conn, error) {
	return l.Listener.Accept()
}
