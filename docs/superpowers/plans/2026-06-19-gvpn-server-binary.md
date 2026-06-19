# gvpn-server Binary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Per-task model assignment (standing rule):** **Sonnet** subagent implements each code task; **Opus** (controller) manages tasks and reviews each diff, and dispatches a fresh **Opus** subagent for the final review; **Haiku** subagent does the `gh` push + PR.

**Goal:** Build the runnable `gvpn-server` binary: a `server.yaml`-configured process that terminates GOST-TLS on `:443`, runs the multiplexed server pipeline over a real kernel TUN with routing + NAT, plus a `gencert` subcommand that self-signs both the GOST server certificate (new cgo capability in `gosttls`) and a standard-TLS certificate (stdlib).

**Architecture:** A new `core/cmd/gvpn-server` command with subcommands `serve` and `gencert`. `serve` loads YAML config, the master key, and the encrypted `FileStore`, then assembles the merged pipeline (`authgate.Gate` → `session.Manager` → `server.Server` over a `wgengine.MuxEngine`) and serves a GOST-TLS listener adapted to `net.Listener`. The host integration (real TUN via `tun.CreateTUN`, IP/route via `ip`, and `iptables` MASQUERADE) sits behind small injectable seams so the assembly is unit-tested with a netstack TUN, a plain-TCP listener, and a recording NAT stub, while production supplies the real ones. `gencert` adds `gosttls.GenerateSelfSignedGOSTCert` (OpenSSL gost-engine keygen + X509 self-sign) and a stdlib standard-cert generator. cgo is confined to `gosttls`; `cmd/gvpn-server` imports `gosttls` so the binary build needs `CGO_ENABLED=1`.

**Tech Stack:** Go 1.24, `gopkg.in/yaml.v3` (config), `golang.zx2c4.com/wireguard/{tun,device}`, OpenSSL 3 + gost engine (cgo, in `gosttls`), stdlib `crypto/x509` / `os/exec`. Toolchain `/home/goodvin/.local/go/bin/go`. Module `github.com/g00dvin/gvpn/core`.

**Design reference:** `docs/superpowers/specs/2026-06-16-user-identity-enrollment-admin-design.md` §11 (certificates), §12 (server.yaml schema). Consumes merged Plan 12 (`server.New(...)(*Server,error)`, `Config{WGPrivateKey,Subnet,LogLevel}`), `gosttls.Listen/Config`, `provision.{LoadMasterKey,NewCipher,NewFileStore}`.

---

## Conventions

- Toolchain: `/home/goodvin/.local/go/bin/go`. The binary and `gosttls` need cgo: run their tests with `CGO_ENABLED=1`. Pure-Go pieces (config) run without. Full command: `cd /home/goodvin/git/gvpn/core && CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./gosttls/ ./cmd/gvpn-server/`.
- Branch `feat/gvpn-server` off `main` (already created; this plan doc is committed there).
- Commits end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- `.gitignore` already covers `gvpn-server`, `*.pem`, `*.key`, `*.crt`, `server.yaml`, `registry.json`. Only `git add` the files each task names.
- **OS-privileged paths are not CI-tested:** real `tun.CreateTUN` and `iptables` need CAP_NET_ADMIN/root. They are isolated behind seams; CI unit-tests the seams with stubs and tests the exact command argv (without executing). The GOST `gencert` **is** CI-testable (CI has the gost engine — `gosttls` tests already run there).

## Decisions locked for this plan

- **Config:** `gopkg.in/yaml.v3`. Schema (design §12): `server.listen`, `tls.{cert,key,ca}`, `wireguard.{private_key,address,subnet}`, `master_key_file` (optional; env `GVPN_MASTER_KEY` wins), `registry`. `wireguard.address` is the server TUN CIDR (e.g. `10.100.0.1/24`); its network is the enrollment subnet.
- **GOST gencert (cgo):** `gosttls.GenerateSelfSignedGOSTCert(cn, certPath, keyPath string, days int) error` — GOST 2012-256 keygen via the loaded gost ENGINE (`gost2012_256`, paramset `A`), X509 v3 self-signed with `md_gost12_256`, SAN `DNS:<cn>`, PEM written 0600 (key) / 0644 (cert). Correctness is pinned by a round-trip test (generate → `gosttls.Listen` + `Dial`). The Go wrapper passes the package `gostEngine` pointer into the C function.
- **Standard gencert:** stdlib `crypto/ecdsa` P-256 self-signed, for the (future) public share page; written by `gvpn-server gencert --standard`.
- **NAT:** shell out to `iptables` for a single `-t nat -A POSTROUTING -s <subnet> -j MASQUERADE` rule (add on start, delete on stop). Shelling to `ip`/`iptables` is allowed (the spec prohibition is only `wg`/`wg-quick`). The NAT and TUN steps are behind interfaces so `serve` is testable without them.
- **Injectable serve seam:** `run(cfg Config, deps serveDeps) error` where `serveDeps{ Listener net.Listener; NewTUN func(addrCIDR string)(tun.Device,error); NAT NAT }`. Tests inject a TCP listener, a netstack TUN, and a recording NAT; `main`'s `serve` builds the real GOST listener (via the adapter), the real TUN factory, and the real iptables NAT.
- **GOST net.Listener adapter:** `gosttls.Listener.Accept()` returns `*gosttls.Conn` (a `net.Conn`); a 3-line embedding adapter satisfies `net.Listener`.

## File structure

```
core/gosttls/gencert.go             GenerateSelfSignedGOSTCert (cgo)                       (CREATE)
core/gosttls/gencert_test.go        round-trip: gen -> Listen/Dial loopback               (CREATE)
core/cmd/gvpn-server/config.go      Config + LoadConfig (server.yaml)                      (CREATE)
core/cmd/gvpn-server/config_test.go                                                        (CREATE)
core/cmd/gvpn-server/stdcert.go     standard ECDSA self-signed cert (stdlib)               (CREATE)
core/cmd/gvpn-server/stdcert_test.go                                                       (CREATE)
core/cmd/gvpn-server/listener.go    gostNetListener adapter                                (CREATE)
core/cmd/gvpn-server/nat.go         NAT iface + iptables impl (argv builder testable)      (CREATE)
core/cmd/gvpn-server/nat_test.go                                                           (CREATE)
core/cmd/gvpn-server/serve.go       run(cfg, deps) assembly + real TUN factory             (CREATE)
core/cmd/gvpn-server/serve_test.go  assembly e2e: netstack TUN + TCP listener + stub NAT   (CREATE)
core/cmd/gvpn-server/main.go        subcommand dispatch (serve | gencert)                  (CREATE)
core/cmd/gvpn-server/main_test.go   gencert subcommand test                                (CREATE)
```

---

## Task 1: server.yaml config loader

**Files:** Create `core/cmd/gvpn-server/config.go`, `core/cmd/gvpn-server/config_test.go`. Adds `gopkg.in/yaml.v3`.

- [ ] **Step 1: Add the dependency**

```bash
cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go get gopkg.in/yaml.v3@v3.0.1
```
Expected: `go.mod`/`go.sum` updated. (If the fetch fails, STOP and report BLOCKED with the exact error.)

- [ ] **Step 2: Write the failing test — create `core/cmd/gvpn-server/config_test.go`:**

```go
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigParsesAndDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	yaml := `
server:
  listen: "0.0.0.0:443"
tls:
  cert: /etc/gvpn/gost.crt
  key: /etc/gvpn/gost.key
  ca: /etc/gvpn/ca.crt
wireguard:
  private_key: "` + "aa" + `"
  address: "10.100.0.1/24"
registry: /etc/gvpn/registry.json
master_key_file: /etc/gvpn/master.key
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Server.Listen != "0.0.0.0:443" {
		t.Fatalf("listen = %q", cfg.Server.Listen)
	}
	if cfg.TLS.Cert != "/etc/gvpn/gost.crt" || cfg.TLS.Key != "/etc/gvpn/gost.key" || cfg.TLS.CA != "/etc/gvpn/ca.crt" {
		t.Fatalf("tls = %+v", cfg.TLS)
	}
	if cfg.WireGuard.Address != "10.100.0.1/24" {
		t.Fatalf("address = %q", cfg.WireGuard.Address)
	}
	if cfg.Registry != "/etc/gvpn/registry.json" || cfg.MasterKeyFile != "/etc/gvpn/master.key" {
		t.Fatalf("registry/master = %q/%q", cfg.Registry, cfg.MasterKeyFile)
	}
	// Subnet is derived from the WireGuard address.
	if cfg.Subnet() != "10.100.0.0/24" {
		t.Fatalf("Subnet() = %q, want 10.100.0.0/24", cfg.Subnet())
	}
}

func TestLoadConfigRejectsMissingRequired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	// Missing tls.cert/key and wireguard.address.
	if err := os.WriteFile(path, []byte("server:\n  listen: \":443\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected validation error for missing required fields")
	}
}

func TestLoadConfigRejectsBadAddress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.yaml")
	yaml := "server:\n  listen: \":443\"\ntls:\n  cert: c\n  key: k\nwireguard:\n  private_key: aa\n  address: not-a-cidr\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error for malformed wireguard.address")
	}
}
```

- [ ] **Step 3: Run to confirm FAIL**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./cmd/gvpn-server/ -run TestLoadConfig -v 2>&1 | tail -20`
Expected: build error — `undefined: LoadConfig`.

- [ ] **Step 4: Create `core/cmd/gvpn-server/config.go`:**

```go
// Command gvpn-server runs the gvpn server (serve) and generates self-signed
// certificates (gencert). It terminates GOST TLS on the configured listener and
// multiplexes authenticated clients onto one WireGuard device over a kernel TUN.
package main

import (
	"fmt"
	"net/netip"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the parsed server.yaml (design §12).
type Config struct {
	Server struct {
		Listen string `yaml:"listen"`
	} `yaml:"server"`
	TLS struct {
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
		CA   string `yaml:"ca"`
	} `yaml:"tls"`
	WireGuard struct {
		PrivateKey string `yaml:"private_key"`
		Address    string `yaml:"address"` // server TUN CIDR, e.g. 10.100.0.1/24
	} `yaml:"wireguard"`
	Registry      string `yaml:"registry"`
	MasterKeyFile string `yaml:"master_key_file"`
}

// LoadConfig reads and validates server.yaml.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("gvpn-server: read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("gvpn-server: parse config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	if c.Server.Listen == "" {
		return fmt.Errorf("gvpn-server: server.listen is required")
	}
	if c.TLS.Cert == "" || c.TLS.Key == "" {
		return fmt.Errorf("gvpn-server: tls.cert and tls.key are required")
	}
	if c.WireGuard.PrivateKey == "" {
		return fmt.Errorf("gvpn-server: wireguard.private_key is required")
	}
	if c.WireGuard.Address == "" {
		return fmt.Errorf("gvpn-server: wireguard.address is required")
	}
	if _, err := netip.ParsePrefix(c.WireGuard.Address); err != nil {
		return fmt.Errorf("gvpn-server: wireguard.address %q: %w", c.WireGuard.Address, err)
	}
	if c.Registry == "" {
		return fmt.Errorf("gvpn-server: registry is required")
	}
	return nil
}

// Subnet returns the tunnel subnet (the masked network of wireguard.address),
// used for enrollment IP allocation.
func (c Config) Subnet() string {
	p, err := netip.ParsePrefix(c.WireGuard.Address)
	if err != nil {
		return ""
	}
	return p.Masked().String()
}

// ServerTUNAddr returns wireguard.address as a netip.Prefix (the server's own
// tunnel address + prefix length).
func (c Config) ServerTUNAddr() (netip.Prefix, error) {
	return netip.ParsePrefix(c.WireGuard.Address)
}
```

- [ ] **Step 5: Run to confirm PASS**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test ./cmd/gvpn-server/ -run TestLoadConfig -v
/home/goodvin/.local/go/bin/go vet ./cmd/gvpn-server/
```
Expected: PASS / clean.

- [ ] **Step 6: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/cmd/gvpn-server/config.go core/cmd/gvpn-server/config_test.go core/go.mod core/go.sum
git commit -m "feat(gvpn-server): server.yaml config loader

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Standard self-signed certificate (stdlib)

**Files:** Create `core/cmd/gvpn-server/stdcert.go`, `core/cmd/gvpn-server/stdcert_test.go`.

- [ ] **Step 1: Write the failing test — create `core/cmd/gvpn-server/stdcert_test.go`:**

```go
package main

import (
	"crypto/tls"
	"path/filepath"
	"testing"
)

func TestGenerateStandardCertIsUsable(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "std.crt")
	keyPath := filepath.Join(dir, "std.key")
	if err := generateStandardCert("vpn.example.com", certPath, keyPath, 365); err != nil {
		t.Fatalf("generateStandardCert: %v", err)
	}
	// The output must load as a usable TLS keypair.
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
}
```

- [ ] **Step 2: Run to confirm FAIL**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go test ./cmd/gvpn-server/ -run TestGenerateStandardCert -v 2>&1 | tail -20`
Expected: build error — `undefined: generateStandardCert`.

- [ ] **Step 3: Create `core/cmd/gvpn-server/stdcert.go`:**

```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// generateStandardCert writes a self-signed P-256 ECDSA certificate and key (PEM)
// for cn, valid for days. It is used for the public (phone-facing) share page,
// which standard browsers must trust; in production an operator supplies a
// publicly-trusted cert instead, but this gives a working dev default.
func generateStandardCert(cn, certPath, keyPath string, days int) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("gvpn-server: gen key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("gvpn-server: serial: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(cn); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{cn}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("gvpn-server: create cert: %w", err)
	}
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("gvpn-server: marshal key: %w", err)
	}
	return writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0o600)
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("gvpn-server: open %s: %w", path, err)
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}
```

- [ ] **Step 4: Run to confirm PASS**

Run:
```bash
cd /home/goodvin/git/gvpn/core
/home/goodvin/.local/go/bin/go test ./cmd/gvpn-server/ -run TestGenerateStandardCert -v
/home/goodvin/.local/go/bin/go vet ./cmd/gvpn-server/
```
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/cmd/gvpn-server/stdcert.go core/cmd/gvpn-server/stdcert_test.go
git commit -m "feat(gvpn-server): standard self-signed cert (stdlib)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: GOST self-signed certificate (cgo in gosttls)

**Files:** Create `core/gosttls/gencert.go`, `core/gosttls/gencert_test.go`.

This adds the OpenSSL gost-engine keygen + X509 self-sign capability. It is cgo and lives in `gosttls`. The Go wrapper passes the package's already-loaded `gostEngine` (a `*C.ENGINE` set by `Init()` in `gosttls.go`) into the C routine. **The round-trip test pins correctness: if the gost engine on the target uses different algorithm/digest/paramset names, the test fails and the names are adjusted — that is expected TDD against an external engine, not a defect.**

- [ ] **Step 1: Write the failing test — create `core/gosttls/gencert_test.go`:**

```go
package gosttls

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestGOSTGencertRoundTrip generates a self-signed GOST cert+key, then proves it
// works by standing up a GOST TLS listener with it and completing a handshake
// from a client that pins the same cert as its CA.
func TestGOSTGencertRoundTrip(t *testing.T) {
	if err := Init(); err != nil {
		t.Skipf("gost engine unavailable: %v", err)
	}
	dir := t.TempDir()
	cert := filepath.Join(dir, "gost.crt")
	key := filepath.Join(dir, "gost.key")
	if err := GenerateSelfSignedGOSTCert("localhost", cert, key, 365); err != nil {
		t.Fatalf("GenerateSelfSignedGOSTCert: %v", err)
	}

	ln, err := Listen("tcp", "127.0.0.1:0", Config{CertFile: cert, KeyFile: key})
	if err != nil {
		t.Fatalf("Listen with generated cert: %v", err)
	}
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := c.Read(buf); err != nil {
			srvErr <- err
			return
		}
		_, err = c.Write([]byte("pong"))
		srvErr <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The client pins the server cert itself as the CA, and verifies CN=localhost.
	cc, err := Dial(ctx, "tcp", ln.Addr().String(), Config{CAFile: cert, ServerName: "localhost"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cc.Close()
	if _, err := cc.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := cc.Read(got); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("got %q, want pong", got)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server: %v", err)
	}
	_ = net.Dial // keep net imported if unused above
}
```

- [ ] **Step 2: Run to confirm FAIL**

Run: `cd /home/goodvin/git/gvpn/core && CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./gosttls/ -run TestGOSTGencert -v 2>&1 | tail -20`
Expected: build error — `undefined: GenerateSelfSignedGOSTCert`.

- [ ] **Step 3: Create `core/gosttls/gencert.go`:**

```go
package gosttls

/*
#cgo pkg-config: libssl libcrypto
#cgo CFLAGS: -Wno-deprecated-declarations
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <stdio.h>
#include <string.h>

// gvpn_gen_gost_selfsigned generates a GOST 2012-256 keypair (via engine e),
// builds a self-signed X509 v3 certificate (CN=cn, SAN DNS:cn, validity days),
// signs it with md_gost12_256, and writes PEM cert and key to the given paths.
// Returns 1 on success, 0 on failure.
static int gvpn_gen_gost_selfsigned(const char *cn, const char *certPath,
                                    const char *keyPath, int days, ENGINE *e) {
    int ok = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    X509 *x = NULL;
    X509_NAME *name = NULL;
    X509_EXTENSION *ext = NULL;
    FILE *fc = NULL, *fk = NULL;
    char san[512];

    int nid = OBJ_txt2nid("gost2012_256");
    if (nid == NID_undef) goto done;
    pctx = EVP_PKEY_CTX_new_id(nid, e);
    if (!pctx) goto done;
    if (EVP_PKEY_keygen_init(pctx) <= 0) goto done;
    if (EVP_PKEY_CTX_ctrl_str(pctx, "paramset", "A") <= 0) goto done;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) goto done;

    x = X509_new();
    if (!x) goto done;
    X509_set_version(x, 2); // v3
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), (long)days * 24L * 3600L);
    if (X509_set_pubkey(x, pkey) != 1) goto done;

    name = X509_get_subject_name(x);
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *)cn, -1, -1, 0) != 1) goto done;
    if (X509_set_issuer_name(x, name) != 1) goto done; // self-signed

    snprintf(san, sizeof(san), "DNS:%s", cn);
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, san);
    if (ext) {
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
        ext = NULL;
    }

    {
        const EVP_MD *md = EVP_get_digestbyname("md_gost12_256");
        if (!md) goto done;
        if (X509_sign(x, pkey, md) == 0) goto done;
    }

    fc = fopen(certPath, "wb");
    if (!fc) goto done;
    if (PEM_write_X509(fc, x) != 1) goto done;
    fk = fopen(keyPath, "wb");
    if (!fk) goto done;
    if (PEM_write_PrivateKey(fk, pkey, NULL, NULL, 0, NULL, NULL) != 1) goto done;

    ok = 1;
done:
    if (fc) fclose(fc);
    if (fk) fclose(fk);
    if (ext) X509_EXTENSION_free(ext);
    if (x) X509_free(x);
    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    return ok;
}
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

// GenerateSelfSignedGOSTCert generates a GOST 2012-256 keypair and a self-signed
// X509 certificate for cn (valid for days), writing PEM cert to certPath and the
// private key to keyPath. The GOST server certificate is pinned by clients (CA
// PEM or fingerprint); it is not part of any public PKI. Requires the gost engine.
func GenerateSelfSignedGOSTCert(cn, certPath, keyPath string, days int) error {
	if err := Init(); err != nil {
		return err
	}
	cCN := C.CString(cn)
	defer C.free(unsafe.Pointer(cCN))
	cCert := C.CString(certPath)
	defer C.free(unsafe.Pointer(cCert))
	cKey := C.CString(keyPath)
	defer C.free(unsafe.Pointer(cKey))

	if C.gvpn_gen_gost_selfsigned(cCN, cCert, cKey, C.int(days), gostEngine) != 1 {
		return fmt.Errorf("gosttls: generate GOST cert: %s", lastError())
	}
	// Tighten the private-key permissions (PEM_write_PrivateKey via fopen uses the
	// process umask; the key must not be world-readable).
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return fmt.Errorf("gosttls: chmod key: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run to confirm PASS**

Run:
```bash
cd /home/goodvin/git/gvpn/core
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./gosttls/ -run TestGOSTGencert -v 2>&1 | tail -30
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./gosttls/
```
Expected: PASS (the generated cert completes a real GOST handshake). If the keygen/sign fails, the OpenSSL error in the message names the issue (e.g. unknown algorithm) — adjust the engine algorithm name (`gost2012_256`), digest (`md_gost12_256`), or paramset and re-run; the round-trip test is the correctness oracle. The whole `gosttls` package must still pass: `CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./gosttls/ 2>&1 | tail -5`.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/gosttls/gencert.go core/gosttls/gencert_test.go
git commit -m "feat(gosttls): self-signed GOST certificate generation (cgo)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: GOST net.Listener adapter

**Files:** Create `core/cmd/gvpn-server/listener.go`. (Tested indirectly by the serve assembly in Task 6; this task adds a tiny compile-time-correct adapter and a trivial test.)

- [ ] **Step 1: Write the failing test — create the adapter test inline in a new file `core/cmd/gvpn-server/listener_test.go`:**

```go
package main

import (
	"net"
	"testing"

	"github.com/g00dvin/gvpn/core/gosttls"
)

// gostListenerSatisfiesNetListener is a compile-time assertion that the adapter
// turns a *gosttls.Listener into a net.Listener.
func TestGostListenerSatisfiesNetListener(t *testing.T) {
	var _ net.Listener = gostNetListener{}
	// Also assert the embedded type is the gosttls listener pointer.
	var l gostNetListener
	if _, ok := interface{}(l.Listener).(*gosttls.Listener); !ok {
		t.Fatal("gostNetListener must embed *gosttls.Listener")
	}
}
```

- [ ] **Step 2: Run to confirm FAIL**

Run: `cd /home/goodvin/git/gvpn/core && CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./cmd/gvpn-server/ -run TestGostListener -v 2>&1 | tail -20`
Expected: build error — `undefined: gostNetListener`.

- [ ] **Step 3: Create `core/cmd/gvpn-server/listener.go`:**

```go
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
```

- [ ] **Step 4: Run to confirm PASS**

Run:
```bash
cd /home/goodvin/git/gvpn/core
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./cmd/gvpn-server/ -run TestGostListener -v
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./cmd/gvpn-server/
```
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/cmd/gvpn-server/listener.go core/cmd/gvpn-server/listener_test.go
git commit -m "feat(gvpn-server): GOST net.Listener adapter

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: NAT (iptables MASQUERADE)

**Files:** Create `core/cmd/gvpn-server/nat.go`, `core/cmd/gvpn-server/nat_test.go`.

The NAT seam is an interface so the serve assembly can be tested with a recording stub. The real impl shells out to `iptables`; its argv is built by a pure function so the exact command is unit-tested without executing `iptables` (which needs root).

- [ ] **Step 1: Write the failing test — create `core/cmd/gvpn-server/nat_test.go`:**

```go
package main

import (
	"reflect"
	"testing"
)

func TestMasqueradeArgs(t *testing.T) {
	add := masqueradeArgs("-A", "10.100.0.0/24")
	wantAdd := []string{"-t", "nat", "-A", "POSTROUTING", "-s", "10.100.0.0/24", "-j", "MASQUERADE"}
	if !reflect.DeepEqual(add, wantAdd) {
		t.Fatalf("add args = %v, want %v", add, wantAdd)
	}
	del := masqueradeArgs("-D", "10.100.0.0/24")
	if del[2] != "-D" {
		t.Fatalf("delete args use %q, want -D", del[2])
	}
}

// recordingNAT is the stub used by serve_test.go; assert it satisfies NAT here.
func TestRecordingNATImplementsNAT(t *testing.T) {
	var _ NAT = (*recordingNAT)(nil)
}
```

- [ ] **Step 2: Run to confirm FAIL**

Run: `cd /home/goodvin/git/gvpn/core && CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./cmd/gvpn-server/ -run 'TestMasqueradeArgs|TestRecordingNAT' -v 2>&1 | tail -20`
Expected: build error — `undefined: masqueradeArgs` / `NAT` / `recordingNAT`.

- [ ] **Step 3: Create `core/cmd/gvpn-server/nat.go`:**

```go
package main

import (
	"fmt"
	"os/exec"
	"sync"
)

// NAT installs and removes the source-NAT rule that lets tunnel clients reach
// the internet through the server.
type NAT interface {
	Enable(subnet string) error
	Disable(subnet string) error
}

// masqueradeArgs builds the iptables argv for the single POSTROUTING MASQUERADE
// rule over subnet. op is "-A" (add) or "-D" (delete).
func masqueradeArgs(op, subnet string) []string {
	return []string{"-t", "nat", op, "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"}
}

// iptablesNAT is the production NAT, shelling out to iptables.
type iptablesNAT struct{}

func (iptablesNAT) Enable(subnet string) error  { return runIptables(masqueradeArgs("-A", subnet)) }
func (iptablesNAT) Disable(subnet string) error { return runIptables(masqueradeArgs("-D", subnet)) }

func runIptables(args []string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("gvpn-server: iptables %v: %w: %s", args, err, out)
	}
	return nil
}

// recordingNAT is a test double that records the subnets it was asked to enable
// and disable without touching the kernel. It is mutex-guarded because Enable/
// Disable run on the server goroutine while the test reads via the accessors.
type recordingNAT struct {
	mu       sync.Mutex
	enabled  []string
	disabled []string
}

func (n *recordingNAT) Enable(subnet string) error {
	n.mu.Lock()
	n.enabled = append(n.enabled, subnet)
	n.mu.Unlock()
	return nil
}

func (n *recordingNAT) Disable(subnet string) error {
	n.mu.Lock()
	n.disabled = append(n.disabled, subnet)
	n.mu.Unlock()
	return nil
}

func (n *recordingNAT) enabledSubnets() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.enabled...)
}

func (n *recordingNAT) disabledSubnets() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.disabled...)
}
```

- [ ] **Step 4: Run to confirm PASS**

Run:
```bash
cd /home/goodvin/git/gvpn/core
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./cmd/gvpn-server/ -run 'TestMasqueradeArgs|TestRecordingNAT' -v
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./cmd/gvpn-server/
```
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/cmd/gvpn-server/nat.go core/cmd/gvpn-server/nat_test.go
git commit -m "feat(gvpn-server): iptables MASQUERADE NAT seam

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: serve assembly (injectable TUN + listener + NAT)

**Files:** Create `core/cmd/gvpn-server/serve.go`, `core/cmd/gvpn-server/serve_test.go`.

`run` assembles the whole pipeline from config + injected seams and blocks serving until the listener closes. The test injects a plain-TCP listener, a netstack TUN, and a recording NAT, then drives a real device through the binary's assembly to prove the wiring — the same end-to-end shape as the merged `core/server` e2e, but exercised through `run`. The real TUN factory (`tun.CreateTUN` + `ip` address/route) lives here too, behind the injected `NewTUN` seam.

- [ ] **Step 1: Write the failing test — create `core/cmd/gvpn-server/serve_test.go`:**

```go
package main

import (
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/session"
	"github.com/g00dvin/gvpn/core/transport"
	"github.com/g00dvin/gvpn/core/wgengine"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestRunAssemblesWorkingTunnel(t *testing.T) {
	t.Setenv("GVPN_MASTER_KEY", strings.Repeat("ab", 32))

	serverWG, _ := wgengine.GeneratePrivateKey()
	serverTunIP := netip.MustParseAddr("10.100.0.1")
	clientTunIP := netip.MustParseAddr("10.100.0.2")

	// Provision a device into the registry the server will load.
	dir := t.TempDir()
	reg := filepath.Join(dir, "registry.json")
	c, _ := provision.NewCipherFromHex(strings.Repeat("ab", 32))
	store, err := provision.NewFileStore(reg, c)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	if _, _, err := store.AddUser("e2e"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	bundle, mat, err := provision.Generate("e2e", clientTunIP.String(), provision.GenerateParams{
		ServerWGPublicKey: serverWG.PublicKey(), ServerEndpoint: "vpn:443", ServerName: "vpn",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := store.AddDevice(provision.Device{
		DeviceID: mat.DeviceID, User: mat.User, WGPublic: mat.WGPublic,
		TunnelIP: mat.TunnelIP, Source: "admin",
	}, mat.AuthPSK); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}

	cfg := Config{Registry: reg}
	cfg.WireGuard.PrivateKey = serverWG.Hex()
	cfg.WireGuard.Address = "10.100.0.1/24"

	// Inject: a plain TCP listener, a netstack TUN, and a recording NAT.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	netCh := make(chan *netstack.Net, 1)
	nat := &recordingNAT{}
	deps := serveDeps{
		Listener: ln,
		NewTUN: func(addrCIDR string) (tun.Device, error) {
			p := netip.MustParsePrefix(addrCIDR)
			dev, n, err := netstack.CreateNetTUN([]netip.Addr{p.Addr()}, nil, 1420)
			if err == nil {
				netCh <- n
			}
			return dev, err
		},
		NAT:      nat,
		LogLevel: device.LogLevelSilent,
	}

	runErr := make(chan error, 1)
	go func() { runErr <- run(cfg, deps) }()
	defer ln.Close()

	// Wait for the server netstack to come up (proves run() built the TUN+server).
	var serverNet *netstack.Net
	select {
	case serverNet = <-netCh:
	case <-time.After(10 * time.Second):
		t.Fatal("run did not build the server TUN")
	}

	// Client: dial the injected listener (plain TCP), auth, bind, WireGuard.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	psk, _ := hex.DecodeString(bundle.AuthPSK)
	devID, _ := provision.ParseDeviceID(bundle.DeviceID)
	if err := authgate.WriteAuth(conn, psk, devID); err != nil {
		t.Fatalf("WriteAuth: %v", err)
	}
	var zsid [16]byte
	var ztok [32]byte
	if _, _, err := session.ClientBind(conn, zsid, ztok); err != nil {
		t.Fatalf("ClientBind: %v", err)
	}
	clientPriv, _ := provision.ParseKey(bundle.WGPrivateKey)
	clientTun, clientNet, err := netstack.CreateNetTUN([]netip.Addr{clientTunIP}, nil, 1420)
	if err != nil {
		t.Fatalf("client TUN: %v", err)
	}
	clientEng, err := wgengine.New(clientTun, transport.NewStreamTransport(conn), wgengine.Config{
		PrivateKey: clientPriv, PeerPublicKey: serverWG.PublicKey(),
		AllowedIPs: []string{"0.0.0.0/0"}, Endpoint: "server:0", Keepalive: 5,
	}, device.LogLevelSilent)
	if err != nil {
		t.Fatalf("client wgengine: %v", err)
	}
	defer clientEng.Close()

	httpLn, err := serverNet.ListenTCP(&net.TCPAddr{IP: serverTunIP.AsSlice(), Port: 80})
	if err != nil {
		t.Fatalf("netstack ListenTCP: %v", err)
	}
	httpSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "served by gvpn-server")
	})}
	go httpSrv.Serve(httpLn)
	defer httpSrv.Close()

	hc := &http.Client{Transport: &http.Transport{DialContext: clientNet.DialContext}, Timeout: 2 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	var body []byte
	for time.Now().Before(deadline) {
		resp, err := hc.Get("http://10.100.0.1/")
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		break
	}
	if string(body) != "served by gvpn-server" {
		t.Fatalf("tunnel body = %q, want the greeting", body)
	}

	// A working tunnel means run() reached Serve, which is after NAT.Enable.
	if en := nat.enabledSubnets(); len(en) != 1 || en[0] != "10.100.0.0/24" {
		t.Fatalf("NAT enabled = %v, want [10.100.0.0/24]", en)
	}

	// Closing the listener makes run() return and tear down (NAT disabled).
	ln.Close()
	select {
	case <-runErr:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after the listener closed")
	}
	if dis := nat.disabledSubnets(); len(dis) != 1 {
		t.Fatalf("NAT disabled = %v, want one teardown", dis)
	}
}
```

- [ ] **Step 2: Run to confirm FAIL**

Run: `cd /home/goodvin/git/gvpn/core && CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./cmd/gvpn-server/ -run TestRunAssembles -v 2>&1 | tail -20`
Expected: build error — `undefined: serveDeps` / `run`.

- [ ] **Step 3: Create `core/cmd/gvpn-server/serve.go`:**

```go
package main

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/provision"
	"github.com/g00dvin/gvpn/core/server"
	"github.com/g00dvin/gvpn/core/session"
	"golang.zx2c4.com/wireguard/tun"
)

// sessionTTL is how long a disconnected session may be resumed.
const sessionTTL = 5 * time.Minute

// serveDeps are the injectable host seams: a listener (GOST TLS in prod, plain
// TCP in tests), a TUN factory (real kernel TUN in prod, netstack in tests), and
// the NAT installer. LogLevel is the wireguard-go log level.
type serveDeps struct {
	Listener net.Listener
	NewTUN   func(addrCIDR string) (tun.Device, error)
	NAT      NAT
	LogLevel int
}

// run assembles the server pipeline from cfg + deps and serves until the
// listener is closed, then tears down (engine close + NAT disable).
func run(cfg Config, deps serveDeps) error {
	key, err := provision.LoadMasterKey(cfg.MasterKeyFile)
	if err != nil {
		return err
	}
	cipher, err := provision.NewCipher(key)
	if err != nil {
		return err
	}
	store, err := provision.NewFileStore(cfg.Registry, cipher)
	if err != nil {
		return err
	}
	wgPriv, err := provision.ParseKey(cfg.WireGuard.PrivateKey)
	if err != nil {
		return fmt.Errorf("gvpn-server: wireguard.private_key: %w", err)
	}

	tunDev, err := deps.NewTUN(cfg.WireGuard.Address)
	if err != nil {
		return fmt.Errorf("gvpn-server: create TUN: %w", err)
	}

	gate := authgate.NewGate(store, nil)
	sessions := session.NewManager(sessionTTL)
	srv, err := server.New(gate, sessions, store, server.Config{
		WGPrivateKey: wgPriv,
		Subnet:       cfg.Subnet(),
		LogLevel:     deps.LogLevel,
	}, tunDev)
	if err != nil {
		tunDev.Close()
		return err
	}

	if err := deps.NAT.Enable(cfg.Subnet()); err != nil {
		srv.Close()
		return fmt.Errorf("gvpn-server: enable NAT: %w", err)
	}
	defer deps.NAT.Disable(cfg.Subnet())
	defer srv.Close()

	// Serve blocks until the listener is closed; it returns that error.
	return srv.Serve(deps.Listener)
}

// realTUN creates a kernel TUN device named gvpn0, assigns addrCIDR, and brings
// it up. It shells out to `ip` (CAP_NET_ADMIN). Production NewTUN.
func realTUN(addrCIDR string) (tun.Device, error) {
	if _, err := netip.ParsePrefix(addrCIDR); err != nil {
		return nil, fmt.Errorf("gvpn-server: address %q: %w", addrCIDR, err)
	}
	dev, err := tun.CreateTUN("gvpn0", 1420)
	if err != nil {
		return nil, err
	}
	name, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, err
	}
	for _, args := range [][]string{
		{"addr", "add", addrCIDR, "dev", name},
		{"link", "set", "dev", name, "up"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			dev.Close()
			return nil, fmt.Errorf("gvpn-server: ip %v: %w: %s", args, err, out)
		}
	}
	return dev, nil
}
```

- [ ] **Step 4: Run to confirm PASS**

Run:
```bash
cd /home/goodvin/git/gvpn/core
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./cmd/gvpn-server/ -run TestRunAssembles -v 2>&1 | tail -30
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./cmd/gvpn-server/
```
Expected: PASS — the injected assembly tunnels HTTP through the binary's `run`, and NAT enable/disable is recorded. (A real handshake runs; allow a few seconds.)

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/cmd/gvpn-server/serve.go core/cmd/gvpn-server/serve_test.go
git commit -m "feat(gvpn-server): serve assembly over injectable TUN/listener/NAT

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: main + subcommand dispatch

**Files:** Create `core/cmd/gvpn-server/main.go`, `core/cmd/gvpn-server/main_test.go`.

`main` wires the real seams for `serve` and implements `gencert` (GOST + standard).

- [ ] **Step 1: Write the failing test — create `core/cmd/gvpn-server/main_test.go`:**

```go
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// gencert (standard) must produce a usable keypair via the dispatch path.
func TestGencertStandardViaDispatch(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "std.crt")
	key := filepath.Join(dir, "std.key")
	if err := dispatch([]string{"gencert", "--standard", "--cn", "vpn.example.com", "--cert", cert, "--key", key}); err != nil {
		t.Fatalf("dispatch gencert: %v", err)
	}
	for _, p := range []string{cert, key} {
		fi, err := os.Stat(p)
		if err != nil || fi.Size() == 0 {
			t.Fatalf("expected non-empty %s: %v", p, err)
		}
	}
}

func TestDispatchUnknownCommand(t *testing.T) {
	if err := dispatch([]string{"frobnicate"}); err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}
```

- [ ] **Step 2: Run to confirm FAIL**

Run: `cd /home/goodvin/git/gvpn/core && CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./cmd/gvpn-server/ -run 'TestGencert|TestDispatch' -v 2>&1 | tail -20`
Expected: build error — `undefined: dispatch`.

- [ ] **Step 3: Create `core/cmd/gvpn-server/main.go`:**

```go
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/g00dvin/gvpn/core/gosttls"
)

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "gvpn-server:", err)
		os.Exit(1)
	}
}

// dispatch routes the subcommand.
func dispatch(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gvpn-server <serve|gencert> [flags]")
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:])
	case "gencert":
		return cmdGencert(args[1:])
	default:
		return fmt.Errorf("unknown command %q (want serve|gencert)", args[0])
	}
}

// cmdServe loads config and runs the server with the real host seams.
func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/gvpn/server.yaml", "path to server.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	ln, err := gosttls.Listen("tcp", cfg.Server.Listen, gosttls.Config{
		CertFile: cfg.TLS.Cert, KeyFile: cfg.TLS.Key,
	})
	if err != nil {
		return fmt.Errorf("gvpn-server: GOST listen: %w", err)
	}
	defer ln.Close()
	return run(cfg, serveDeps{
		Listener: gostNetListener{Listener: ln},
		NewTUN:   realTUN,
		NAT:      iptablesNAT{},
		LogLevel: 0, // device.LogLevelSilent
	})
}

// cmdGencert generates a GOST server cert (default) or a standard cert (--standard).
func cmdGencert(args []string) error {
	fs := flag.NewFlagSet("gencert", flag.ContinueOnError)
	standard := fs.Bool("standard", false, "generate a standard (non-GOST) cert for the share page")
	cn := fs.String("cn", "", "certificate common name / SAN (required)")
	certPath := fs.String("cert", "", "output certificate path (required)")
	keyPath := fs.String("key", "", "output private key path (required)")
	days := fs.Int("days", 825, "validity in days")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cn == "" || *certPath == "" || *keyPath == "" {
		return fmt.Errorf("gencert: --cn, --cert and --key are required")
	}
	if *standard {
		if err := generateStandardCert(*cn, *certPath, *keyPath, *days); err != nil {
			return err
		}
		fmt.Printf("wrote standard cert %s / key %s\n", *certPath, *keyPath)
		return nil
	}
	if err := gosttls.GenerateSelfSignedGOSTCert(*cn, *certPath, *keyPath, *days); err != nil {
		return err
	}
	fmt.Printf("wrote GOST cert %s / key %s\n", *certPath, *keyPath)
	return nil
}
```

- [ ] **Step 4: Run to confirm PASS**

Run:
```bash
cd /home/goodvin/git/gvpn/core
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./cmd/gvpn-server/ -v 2>&1 | tail -30
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./cmd/gvpn-server/
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go build ./cmd/gvpn-server/
```
Expected: PASS / clean; the binary builds.

- [ ] **Step 5: Commit**

```bash
cd /home/goodvin/git/gvpn
git add core/cmd/gvpn-server/main.go core/cmd/gvpn-server/main_test.go
git commit -m "feat(gvpn-server): main + serve/gencert subcommand dispatch

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 8: Final review + PR

**Files:** none (verification + PR only).

- [ ] **Step 1: Whole-module verification (cgo on)**

```bash
cd /home/goodvin/git/gvpn/core
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test -race ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./...
CGO_ENABLED=1 /home/goodvin/.local/go/bin/go build ./...
```
Expected: all PASS / clean. (`gosttls` and `cmd/gvpn-server` need cgo + the gost engine, present on this host and CI.)

- [ ] **Step 2: Confirm the cgo boundary**

Run: `cd /home/goodvin/git/gvpn/core && /home/goodvin/.local/go/bin/go list -deps ./cmd/gvpn-server/ | grep -E 'gosttls' && echo "expected: cmd depends on gosttls (cgo binary)"`
Expected: prints the gosttls dep (the binary is intentionally a cgo binary). Confirm no OTHER package regressed to cgo: `/home/goodvin/.local/go/bin/go list -deps ./provision/ ./wgengine/ ./server/ | grep -i gosttls || echo "OK: core libs stay cgo-free"`.

- [ ] **Step 3: Opus final code + security review** (controller dispatches a fresh Opus subagent)

Review focus: the GOST `gencert` C (no memory leaks on the error `goto` paths; key written 0600; the generated cert actually completes a GOST handshake — proven by the round-trip test; the Go wrapper passes the loaded engine correctly and never logs key material); config validation (required fields, malformed CIDR rejected; secrets — master key — never in `server.yaml`, only env/key-file); the serve assembly ordering (TUN created → server.New → NAT enable; teardown reverses it: NAT disable + srv.Close on listener close, no leak); the `run` error paths close the TUN/engine they created; NAT argv exactly one POSTROUTING MASQUERADE rule, added on start and deleted on stop; the GOST net.Listener adapter returns `*gosttls.Conn` as `net.Conn`; `serve_test` proves a real device tunnels HTTP through the binary's `run`; no secret logging (WG key, PSKs, master key); the core libraries (`provision`/`wgengine`/`server`) stay cgo-free while only the binary + `gosttls` use cgo. Note any cgo memory issue, secret leak, teardown leak, or validation gap as Critical/Important.

- [ ] **Step 4: Push and open PR** (trivial / `gh` — Haiku)

```bash
cd /home/goodvin/git/gvpn
git push -u origin feat/gvpn-server
gh pr create --base main --head feat/gvpn-server \
  --title "gvpn-server binary: serve (GOST TLS + TUN + NAT) and gencert (GOST + standard)" \
  --body "The runnable gvpn-server binary, assembling the merged stack behind a server.yaml config, plus self-signed certificate generation.

- config: server.yaml loader (gopkg.in/yaml.v3) — server.listen, tls.{cert,key,ca}, wireguard.{private_key,address}, registry, master_key_file; Subnet() derived from wireguard.address.
- gencert: GOST server cert via a new cgo capability in gosttls (OpenSSL gost-engine keygen + X509 self-sign, md_gost12_256, key 0600) — pinned by a round-trip handshake test; standard ECDSA cert via stdlib for the share page.
- serve: run(cfg, deps) assembles master key -> FileStore -> gate -> sessions -> server.New over a kernel TUN -> GOST listener (net.Listener adapter) -> Serve; iptables MASQUERADE enabled on start, removed on stop. Host seams (real TUN via tun.CreateTUN + ip, iptables NAT) are injectable; the assembly is unit-tested with a netstack TUN + TCP listener + recording NAT driving a real device tunnel through run().
- main: serve | gencert subcommand dispatch.

cgo is confined to gosttls; cmd/gvpn-server is intentionally a cgo binary; provision/wgengine/server stay cgo-free. OS-privileged paths (real TUN, iptables) are behind seams and integration/manual-tested; everything else (config, both gencerts, the GOST listener adapter, the full serve assembly) is CI-tested under -race.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

---

## Self-Review

**Spec coverage (design §11, §12):** server.yaml schema + loader (Task 1); GOST gencert via the OpenSSL gost engine, key 0600, self-signed/pinned (Task 3); standard gencert via stdlib for the share page (Task 2); the GOST `net.Listener` adapter over `*gosttls.Listener` (Task 4); real kernel TUN (`tun.CreateTUN` + `ip`) and iptables MASQUERADE behind seams (Tasks 5–6); the `serve` assembly wiring config → master key → FileStore → gate → sessions → `server.New` → GOST listener → `Serve` with NAT lifecycle (Task 6); `serve`/`gencert` dispatch (Task 7). The session sweep is already inside `server.Server` (Plan 12), so the binary does not re-wire it. The admin API / web UI / public share page are the next plan (the share-page standard cert is generated here, ready for it). No ACME (per the design).

**Placeholder scan:** none — every step is complete code. The cgo engine algorithm/digest/paramset names in Task 3 (`gost2012_256`, `md_gost12_256`, paramset `A`) are the known OpenSSL gost-engine names, with the round-trip handshake test as the correctness oracle (TDD against an external engine — if a name differs on the target, the test fails and it is corrected; not a plan defect). The only deliberately-not-CI-tested code is `realTUN` (needs `tun.CreateTUN` + CAP_NET_ADMIN) and `iptablesNAT.Enable/Disable` (need root) — both are thin wrappers behind the `serveDeps.NewTUN`/`NAT` seams that the assembly test exercises with stubs; their argv is unit-tested (`masqueradeArgs`) and their bodies are integration/manual-verified.

**Type consistency:** `Config` with nested `Server/TLS/WireGuard` + `Registry`/`MasterKeyFile`, `LoadConfig(string)(Config,error)`, `Config.Subnet()`/`ServerTUNAddr()`; `generateStandardCert(cn,certPath,keyPath string, days int) error` + `writePEM`; `gosttls.GenerateSelfSignedGOSTCert(cn,certPath,keyPath string, days int) error` (passes package `gostEngine`); `gostNetListener{*gosttls.Listener}` with `Accept() (net.Conn,error)`; `NAT` iface (`Enable`/`Disable(subnet string) error`), `masqueradeArgs(op,subnet string) []string`, `iptablesNAT`, `recordingNAT`; `serveDeps{Listener net.Listener; NewTUN func(string)(tun.Device,error); NAT NAT; LogLevel int}`, `run(Config, serveDeps) error`, `realTUN(string)(tun.Device,error)`; `dispatch([]string) error`, `cmdServe`/`cmdGencert`. Consumes merged `server.New(gate,sessions,store,server.Config{WGPrivateKey,Subnet,LogLevel},tunDev)(*Server,error)` and `server.Serve(net.Listener)`, `provision.{LoadMasterKey,NewCipher,NewFileStore,ParseKey,Generate,ParseDeviceID}`, `gosttls.{Listen,Dial,Config,Init}`.
