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

// Defined per-platform in engine_other.go / engine_android.go: makes
// ENGINE_by_id("gost") resolvable and returns the (not-yet-initialized)
// engine, or NULL.
ENGINE *gvpn_register_gost(void);
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
		e := C.gvpn_register_gost()
		if e == nil {
			initErr = fmt.Errorf("gosttls: failed to load gost engine (install libengine-gost-openssl on the server; on Android it is statically linked): %s", lastError())
			return
		}
		if C.ENGINE_init(e) == 0 {
			C.ENGINE_free(e)
			initErr = fmt.Errorf("gosttls: ENGINE_init(gost) failed: %s", lastError())
			return
		}
		C.ENGINE_set_default(e, C.ENGINE_METHOD_ALL)
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
