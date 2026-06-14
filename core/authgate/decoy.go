package authgate

import (
	"fmt"
	"io"
	"net"
	"time"
)

// Decoy handles connections that fail authentication. The censorship-resistance
// design (§3) requires serving these as a real website rather than dropping
// them, so an active prober sees an ordinary HTTPS origin.
type Decoy interface {
	// Handle takes ownership of client and must close it. prefix is the bytes
	// already read from client during the auth attempt; they are replayed to the
	// origin first so the proxied request is intact.
	Handle(client net.Conn, prefix []byte) error
}

// TCPDecoy transparently reverse-proxies the (already TLS-terminated)
// connection to a plain-TCP decoy origin, e.g. a local web server serving a
// plausible site matching the server's GOST cert domain.
type TCPDecoy struct {
	Origin      string        // host:port of the decoy origin
	DialTimeout time.Duration // <=0 => 5s
}

func (d TCPDecoy) dialTimeout() time.Duration {
	if d.DialTimeout <= 0 {
		return 5 * time.Second
	}
	return d.DialTimeout
}

// Handle implements Decoy.
func (d TCPDecoy) Handle(client net.Conn, prefix []byte) error {
	defer client.Close()

	origin, err := net.DialTimeout("tcp", d.Origin, d.dialTimeout())
	if err != nil {
		return fmt.Errorf("authgate: dial decoy %q: %w", d.Origin, err)
	}
	defer origin.Close()

	if len(prefix) > 0 {
		if _, err := origin.Write(prefix); err != nil {
			return fmt.Errorf("authgate: replay prefix to decoy: %w", err)
		}
	}

	// Splice both directions. Return once either ends; the deferred Close calls
	// unblock the other io.Copy (errc is buffered so neither goroutine leaks).
	errc := make(chan error, 2)
	go func() { _, e := io.Copy(origin, client); errc <- e }()
	go func() { _, e := io.Copy(client, origin); errc <- e }()
	<-errc
	return nil
}
