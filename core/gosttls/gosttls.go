// Package gosttls provides GOST TLS (TLS 1.2 + GOST ciphersuites) via a CGO
// binding to OpenSSL 3.x and the "gost" engine. It exposes net.Conn-compatible
// client and server connections that plug into the transport Dialer.
//
// Requires OpenSSL 3.x dev libraries and the gost engine
// (Debian: libssl-dev + libengine-gost-openssl).
package gosttls

/*
#cgo pkg-config: libssl libcrypto
#cgo CFLAGS: -Wno-deprecated-declarations
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <stdlib.h>

static ENGINE *gvpn_load_gost_engine(void) {
    ENGINE *e = ENGINE_by_id("gost");
    if (e == NULL) return NULL;
    if (ENGINE_init(e) == 0) {
        ENGINE_free(e);
        return NULL;
    }
    ENGINE_set_default(e, ENGINE_METHOD_ALL);
    return e;
}
*/
import "C"
import (
	"fmt"
	"sync"
	"unsafe"
)

var (
	initOnce   sync.Once
	initErr    error
	gostEngine *C.ENGINE
)

// Init performs one-time OpenSSL + gost engine initialization. It is safe to
// call repeatedly and concurrently; only the first call does work. All gosttls
// constructors call it implicitly.
func Init() error {
	initOnce.Do(func() {
		if C.OPENSSL_init_ssl(0, nil) != 1 {
			initErr = fmt.Errorf("gosttls: OPENSSL_init_ssl failed: %s", lastError())
			return
		}
		e := C.gvpn_load_gost_engine()
		if e == nil {
			initErr = fmt.Errorf("gosttls: failed to load gost engine (install libengine-gost-openssl): %s", lastError())
			return
		}
		gostEngine = e
	})
	return initErr
}

// Version returns the linked OpenSSL version string.
func Version() string {
	return C.GoString(C.OpenSSL_version(C.OPENSSL_VERSION))
}

// lastError drains one OpenSSL error into a string for diagnostics.
func lastError() string {
	code := C.ERR_get_error()
	if code == 0 {
		return "no OpenSSL error"
	}
	cbuf := (*C.char)(C.malloc(256))
	defer C.free(unsafe.Pointer(cbuf))
	C.ERR_error_string_n(code, cbuf, 256)
	return C.GoString(cbuf)
}
