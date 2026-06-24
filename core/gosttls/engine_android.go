//go:build android

package gosttls

/*
#cgo pkg-config: gostengine
#cgo CFLAGS: -Wno-deprecated-declarations
#include <openssl/engine.h>

// ENGINE_load_gost is the public "library form" entry point of the
// statically-linked gost engine (libgost.a, built by
// scripts/android/build-gost-engine-android.sh with -DBUILDING_ENGINE_AS_LIBRARY).
// It does ENGINE_new + make_gost_engine + ENGINE_add internally.
extern void ENGINE_load_gost(void);

// gvpn_register_gost registers the statically-linked gost engine so that
// ENGINE_by_id("gost") resolves it, then returns the engine (not yet
// initialized) or NULL. There is no ENGINESDIR / gost.so on Android.
//
// External linkage (not static): it is defined here but called from the cgo
// preamble of gosttls.go, a separate translation unit.
ENGINE *gvpn_register_gost(void) {
    ENGINE_load_gost();
    return ENGINE_by_id("gost");
}
*/
import "C"
