//go:build !android

package gosttls

/*
#cgo pkg-config: libssl libcrypto
#cgo CFLAGS: -Wno-deprecated-declarations
#include <openssl/engine.h>

// gvpn_register_gost makes ENGINE_by_id("gost") resolvable and returns the
// engine (not yet initialized), or NULL. On non-Android platforms the gost
// engine is a system shared object found via OpenSSL's ENGINESDIR.
//
// External linkage (not static): it is defined here but called from the cgo
// preamble of gosttls.go, a separate translation unit.
ENGINE *gvpn_register_gost(void) {
    return ENGINE_by_id("gost");
}
*/
import "C"
