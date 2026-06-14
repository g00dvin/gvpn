package gosttls

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// generateGOSTFixtures creates a self-signed GOST 2012-256 certificate and its
// private key in a temp dir via the openssl CLI and the gost engine, returning
// their paths. Certificates are deliberately not committed (see .gitignore:
// "Secrets & certificates — never commit"); each run mints fresh ones. The
// engine is located through ENGINESDIR, so no openssl.cnf is required.
func generateGOSTFixtures(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skipf("openssl CLI not available: %v", err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "gost.crt")
	keyFile = filepath.Join(dir, "gost.key")
	cmd := exec.Command("openssl", "req", "-engine", "gost", "-x509",
		"-newkey", "gost2012_256", "-pkeyopt", "paramset:A", "-nodes",
		"-keyout", keyFile, "-out", certFile,
		"-subj", "/CN=gvpn-test", "-days", "3650")
	// Strip any inherited OPENSSL_CONF so the gost engine is found purely via
	// ENGINESDIR rather than a stale config pointing elsewhere.
	cmd.Env = envWithout(os.Environ(), "OPENSSL_CONF")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate GOST cert (need gost engine): %v\n%s", err, out)
	}
	return certFile, keyFile
}

func envWithout(env []string, key string) []string {
	out := env[:0:0]
	for _, kv := range env {
		if !strings.HasPrefix(kv, key+"=") {
			out = append(out, kv)
		}
	}
	return out
}

// testConfig builds a Config from freshly generated GOST fixtures. The
// self-signed cert serves as both the server certificate and the client's
// verifying CA.
func testConfig(t *testing.T) Config {
	t.Helper()
	cert, key := generateGOSTFixtures(t)
	return Config{
		CertFile:   cert,
		KeyFile:    key,
		CAFile:     cert,
		ServerName: "gvpn-test",
	}
}

func TestNewServerCtx(t *testing.T) {
	ctx, err := newServerCtx(testConfig(t))
	if err != nil {
		t.Fatalf("newServerCtx: %v", err)
	}
	if ctx == nil {
		t.Fatal("newServerCtx returned nil ctx with no error")
	}
	freeCtx(ctx)
}

func TestNewClientCtx(t *testing.T) {
	ctx, err := newClientCtx(testConfig(t))
	if err != nil {
		t.Fatalf("newClientCtx: %v", err)
	}
	if ctx == nil {
		t.Fatal("newClientCtx returned nil ctx with no error")
	}
	freeCtx(ctx)
}

// A bad cert path must surface an error, not silently succeed.
func TestNewServerCtxBadCert(t *testing.T) {
	cfg := testConfig(t)
	cfg.CertFile = filepath.Join(t.TempDir(), "does-not-exist.crt")
	if _, err := newServerCtx(cfg); err == nil {
		t.Fatal("newServerCtx with missing cert: want error, got nil")
	}
}
