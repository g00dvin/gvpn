package gosttls

/*
#cgo pkg-config: libssl libcrypto
#cgo CFLAGS: -Wno-deprecated-declarations
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>

// SSL_CTX_set_min/max_proto_version are function-like macros (SSL_CTX_ctrl),
// which cgo cannot call directly; wrap them as real functions.
static int gvpn_set_min_proto(SSL_CTX *ctx, int v) { return SSL_CTX_set_min_proto_version(ctx, v); }
static int gvpn_set_max_proto(SSL_CTX *ctx, int v) { return SSL_CTX_set_max_proto_version(ctx, v); }
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Config holds the file paths and verification parameters for a GOST TLS
// endpoint. CertFile/KeyFile are the server's GOST certificate and private key.
// CAFile is the CA certificate the client uses to verify the server. ServerName
// is the expected server certificate name (used client-side for SNI and the
// hostname check, set up in the Conn layer).
type Config struct {
	CertFile   string
	KeyFile    string
	CAFile     string
	ServerName string
}

// gostCipherList pins the GOST 2012 TLS 1.2 ciphersuites provided by the gost
// engine on this OpenSSL build (verified with `openssl ciphers`). The older
// GOST2012-GOST8912-GOST8912 suite is TLSv1-only here (exposed as the LEGACY-/
// IANA- prefixed names) and is therefore excluded by the TLS 1.2 floor.
const gostCipherList = "GOST2012-MAGMA-MAGMAOMAC:GOST2012-KUZNYECHIK-KUZNYECHIKOMAC"

// newServerCtx builds a server SSL_CTX pinned to TLS 1.2 with the GOST cipher
// list, loading the certificate chain and private key from cfg. The caller
// owns the returned context and must release it with freeCtx.
func newServerCtx(cfg Config) (*C.SSL_CTX, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	ctx := C.SSL_CTX_new(C.TLS_server_method())
	if ctx == nil {
		return nil, fmt.Errorf("gosttls: SSL_CTX_new(server): %s", lastError())
	}
	if err := pinTLS12(ctx); err != nil {
		C.SSL_CTX_free(ctx)
		return nil, err
	}

	cCert := C.CString(cfg.CertFile)
	defer C.free(unsafe.Pointer(cCert))
	if C.SSL_CTX_use_certificate_chain_file(ctx, cCert) != 1 {
		C.SSL_CTX_free(ctx)
		return nil, fmt.Errorf("gosttls: load certificate %q: %s", cfg.CertFile, lastError())
	}

	cKey := C.CString(cfg.KeyFile)
	defer C.free(unsafe.Pointer(cKey))
	if C.SSL_CTX_use_PrivateKey_file(ctx, cKey, C.SSL_FILETYPE_PEM) != 1 {
		C.SSL_CTX_free(ctx)
		return nil, fmt.Errorf("gosttls: load private key %q: %s", cfg.KeyFile, lastError())
	}
	if C.SSL_CTX_check_private_key(ctx) != 1 {
		C.SSL_CTX_free(ctx)
		return nil, fmt.Errorf("gosttls: private key does not match certificate: %s", lastError())
	}

	if err := setGOSTCiphers(ctx); err != nil {
		C.SSL_CTX_free(ctx)
		return nil, err
	}
	return ctx, nil
}

// newClientCtx builds a client SSL_CTX pinned to TLS 1.2 with the GOST cipher
// list. It loads the CA from cfg and requires peer (server) verification.
// Certificate verification is never disabled. The caller owns the returned
// context and must release it with freeCtx.
func newClientCtx(cfg Config) (*C.SSL_CTX, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	ctx := C.SSL_CTX_new(C.TLS_client_method())
	if ctx == nil {
		return nil, fmt.Errorf("gosttls: SSL_CTX_new(client): %s", lastError())
	}
	if err := pinTLS12(ctx); err != nil {
		C.SSL_CTX_free(ctx)
		return nil, err
	}

	cCA := C.CString(cfg.CAFile)
	defer C.free(unsafe.Pointer(cCA))
	if C.SSL_CTX_load_verify_locations(ctx, cCA, nil) != 1 {
		C.SSL_CTX_free(ctx)
		return nil, fmt.Errorf("gosttls: load CA %q: %s", cfg.CAFile, lastError())
	}
	// Require the server to present a certificate that chains to the CA.
	C.SSL_CTX_set_verify(ctx, C.SSL_VERIFY_PEER, nil)

	if err := setGOSTCiphers(ctx); err != nil {
		C.SSL_CTX_free(ctx)
		return nil, err
	}
	return ctx, nil
}

// pinTLS12 fixes both the minimum and maximum protocol version to TLS 1.2, so
// only the GOST TLS 1.2 ciphersuites can be negotiated.
func pinTLS12(ctx *C.SSL_CTX) error {
	if C.gvpn_set_min_proto(ctx, C.TLS1_2_VERSION) != 1 {
		return fmt.Errorf("gosttls: set min proto TLS 1.2: %s", lastError())
	}
	if C.gvpn_set_max_proto(ctx, C.TLS1_2_VERSION) != 1 {
		return fmt.Errorf("gosttls: set max proto TLS 1.2: %s", lastError())
	}
	return nil
}

// setGOSTCiphers restricts the context to the GOST cipher list.
func setGOSTCiphers(ctx *C.SSL_CTX) error {
	cList := C.CString(gostCipherList)
	defer C.free(unsafe.Pointer(cList))
	if C.SSL_CTX_set_cipher_list(ctx, cList) != 1 {
		return fmt.Errorf("gosttls: set GOST cipher list %q: %s", gostCipherList, lastError())
	}
	return nil
}

// freeCtx releases an SSL_CTX allocated by the context builders.
func freeCtx(ctx *C.SSL_CTX) {
	if ctx != nil {
		C.SSL_CTX_free(ctx)
	}
}
