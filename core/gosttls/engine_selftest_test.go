package gosttls

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEngineSelfTest proves the gost engine loads and performs GOST crypto:
// Init() succeeds and a GOST-2012-256 self-signed certificate is generated
// entirely in-process (engine keygen + md_gost12_256 self-sign). This is the
// source compiled for android/amd64 and run on the emulator (milestone 3).
//
// When GVPN_REQUIRE_GOST=1 the engine MUST be present: an Init failure is fatal
// rather than skipped, so CI / the emulator cannot pass without a working engine.
func TestEngineSelfTest(t *testing.T) {
	required := os.Getenv("GVPN_REQUIRE_GOST") == "1"
	if err := Init(); err != nil {
		if required {
			t.Fatalf("gost engine required but unavailable: %v", err)
		}
		t.Skipf("gost engine unavailable: %v", err)
	}

	dir := t.TempDir()
	cert := filepath.Join(dir, "selftest.crt")
	key := filepath.Join(dir, "selftest.key")
	if err := GenerateSelfSignedGOSTCert("selftest.gvpn", cert, key, 1); err != nil {
		t.Fatalf("GOST keygen/self-sign failed (engine not doing GOST crypto): %v", err)
	}
	for _, p := range []string{cert, key} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("expected output %s: %v", p, err)
		}
		if fi.Size() == 0 {
			t.Fatalf("output %s is empty", p)
		}
	}
}
