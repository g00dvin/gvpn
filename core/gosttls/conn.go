package gosttls

/*
#cgo pkg-config: libssl libcrypto
#cgo CFLAGS: -Wno-deprecated-declarations
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>

// SSL_set_tlsext_host_name is a function-like macro (SSL_ctrl); wrap it so cgo
// can call it. Used to send SNI on the client.
static int gvpn_set_sni(SSL *ssl, const char *name) {
    return (int)SSL_set_tlsext_host_name(ssl, name);
}
*/
import "C"

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Conn is a net.Conn implemented over an OpenSSL SSL* using a blocking dup of
// the underlying TCP socket. The blocking model is the simplest correct first
// cut; a memory-BIO/netpoller variant (with working deadlines) is a later perf
// task. Deadlines delegate to the original socket and are therefore best-effort
// against the dup'd fd that SSL drives.
// The SSL object is not safe for unsynchronized concurrent use. WireGuard drives
// the connection full-duplex (a reader goroutine and a writer goroutine at once),
// so SSL_read and SSL_write are guarded by separate locks: this permits one
// concurrent reader and one concurrent writer (the WireGuard pattern) while
// serializing any extra readers/writers and the SSL_free in Close. Renegotiation
// is disabled at the context level (see gvpn_disable_renegotiation) so a read
// never needs to drive the write half.
type Conn struct {
	ssl     *C.SSL
	file    *os.File // dup of raw's fd, in blocking mode; drives SSL I/O
	raw     net.Conn // original connection, kept for addrs/lifetime
	readMu  sync.Mutex
	writeMu sync.Mutex

	closeOnce sync.Once
}

var _ net.Conn = (*Conn)(nil)

type handshakeMode int

const (
	modeClient handshakeMode = iota
	modeServer
)

// Dial establishes a GOST TLS client connection to addr. It verifies the
// server certificate against cfg.CAFile and, when cfg.ServerName is set, sends
// it as SNI and requires the certificate to match that name.
func Dial(ctx context.Context, network, addr string, cfg Config) (*Conn, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	sslctx, err := newClientCtx(cfg)
	if err != nil {
		return nil, err
	}
	// SSL_new takes its own reference to the ctx; drop ours once Dial returns.
	defer C.SSL_CTX_free(sslctx)

	var d net.Dialer
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	conn, err := newConn(sslctx, raw, modeClient, cfg.ServerName)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// Listener accepts GOST TLS server connections.
type Listener struct {
	ln  net.Listener
	ctx *C.SSL_CTX
}

// Listen creates a GOST TLS listener bound to addr using the server
// certificate and key in cfg.
func Listen(network, addr string, cfg Config) (*Listener, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	sslctx, err := newServerCtx(cfg)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		C.SSL_CTX_free(sslctx)
		return nil, err
	}
	return &Listener{ln: ln, ctx: sslctx}, nil
}

// Accept waits for and returns the next GOST TLS connection, completing the
// server handshake before returning.
func (l *Listener) Accept() (*Conn, error) {
	raw, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	conn, err := newConn(l.ctx, raw, modeServer, "")
	if err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// Close stops listening and releases the server context.
func (l *Listener) Close() error {
	err := l.ln.Close()
	if l.ctx != nil {
		C.SSL_CTX_free(l.ctx)
		l.ctx = nil
	}
	return err
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// newConn wraps an accepted/dialed TCP connection in an SSL object and runs the
// handshake. On error it closes the dup'd fd it created but leaves raw to the
// caller. On success the returned Conn owns both raw and the dup.
func newConn(sslctx *C.SSL_CTX, raw net.Conn, mode handshakeMode, serverName string) (*Conn, error) {
	tcp, ok := raw.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("gosttls: connection is %T, want *net.TCPConn", raw)
	}
	// File dups the socket fd and puts it into blocking mode, which is what the
	// blocking SSL_* calls require.
	file, err := tcp.File()
	if err != nil {
		return nil, fmt.Errorf("gosttls: dup socket fd: %w", err)
	}

	ssl := C.SSL_new(sslctx)
	if ssl == nil {
		file.Close()
		return nil, fmt.Errorf("gosttls: SSL_new: %s", lastError())
	}
	if C.SSL_set_fd(ssl, C.int(file.Fd())) != 1 {
		C.SSL_free(ssl)
		file.Close()
		return nil, fmt.Errorf("gosttls: SSL_set_fd: %s", lastError())
	}

	if mode == modeClient && serverName != "" {
		if err := setClientVerifyName(ssl, serverName); err != nil {
			C.SSL_free(ssl)
			file.Close()
			return nil, err
		}
	}

	var ret C.int
	if mode == modeClient {
		ret = C.SSL_connect(ssl)
	} else {
		ret = C.SSL_accept(ssl)
	}
	if ret != 1 {
		err := fmt.Errorf("gosttls: handshake failed: %s (ssl_error=%d)",
			lastError(), int(C.SSL_get_error(ssl, ret)))
		C.SSL_free(ssl)
		file.Close()
		return nil, err
	}

	return &Conn{ssl: ssl, file: file, raw: raw}, nil
}

// setClientVerifyName sends SNI and enables hostname verification for name.
func setClientVerifyName(ssl *C.SSL, name string) error {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	if C.gvpn_set_sni(ssl, cName) != 1 {
		return fmt.Errorf("gosttls: set SNI %q: %s", name, lastError())
	}
	// SSL_set1_host makes the handshake fail unless the peer certificate
	// matches name (checked against SAN, falling back to CN).
	if C.SSL_set1_host(ssl, cName) != 1 {
		return fmt.Errorf("gosttls: set verify host %q: %s", name, lastError())
	}
	return nil
}

// Read reads decrypted application data. Safe to call concurrently with Write
// (one reader, one writer); extra concurrent readers are serialized.
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.ssl == nil {
		return 0, io.EOF
	}
	n := C.SSL_read(c.ssl, unsafe.Pointer(&p[0]), C.int(len(p)))
	if n > 0 {
		return int(n), nil
	}
	return 0, c.ioError("read", n)
}

// Write encrypts and sends all of p. Safe to call concurrently with Read (one
// reader, one writer); extra concurrent writers are serialized.
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.ssl == nil {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for total < len(p) {
		n := C.SSL_write(c.ssl, unsafe.Pointer(&p[total]), C.int(len(p)-total))
		if n <= 0 {
			return total, c.ioError("write", n)
		}
		total += int(n)
	}
	return total, nil
}

// ioError maps an SSL_read/SSL_write non-positive return to a Go error,
// translating a clean peer shutdown to io.EOF.
func (c *Conn) ioError(op string, ret C.int) error {
	switch code := C.SSL_get_error(c.ssl, ret); code {
	case C.SSL_ERROR_ZERO_RETURN:
		return io.EOF
	case C.SSL_ERROR_SYSCALL:
		if lastError() == "no OpenSSL error" {
			// Peer dropped the connection without a close_notify.
			return io.ErrUnexpectedEOF
		}
		return fmt.Errorf("gosttls: %s: syscall: %s", op, lastError())
	default:
		return fmt.Errorf("gosttls: %s: %s (ssl_error=%d)", op, lastError(), int(code))
	}
}

// Close shuts down the TLS session and releases all resources exactly once. It
// is safe to call while another goroutine is blocked in Read or Write: the
// socket is shut down first to interrupt the blocking SSL_read/SSL_write, then
// the SSL object is freed under both I/O locks so SSL_free never races a live
// SSL_* call.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		// Interrupt any in-flight blocking SSL_read/SSL_write on the dup'd socket
		// so the lock acquisitions below cannot block forever. Best-effort: a
		// graceful close_notify is skipped in favor of concurrency safety.
		if c.file != nil {
			syscall.Shutdown(int(c.file.Fd()), syscall.SHUT_RDWR)
		}
		c.readMu.Lock()
		c.writeMu.Lock()
		if c.ssl != nil {
			C.SSL_free(c.ssl)
			c.ssl = nil
		}
		c.writeMu.Unlock()
		c.readMu.Unlock()
		if c.file != nil {
			c.file.Close()
		}
		if c.raw != nil {
			err = c.raw.Close()
		}
	})
	return err
}

// CipherName returns the negotiated cipher suite name (e.g. for asserting a
// GOST suite was selected), or "" if no cipher is active.
func CipherName(c *Conn) string {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.ssl == nil {
		return ""
	}
	cipher := C.SSL_get_current_cipher(c.ssl)
	if cipher == nil {
		return ""
	}
	return C.GoString(C.SSL_CIPHER_get_name(cipher))
}

// net.Conn address and deadline methods delegate to the original socket. Note
// the deadline caveat in the Conn doc comment.
func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
