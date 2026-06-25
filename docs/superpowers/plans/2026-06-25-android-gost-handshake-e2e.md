# Android GOST Handshake + Control e2e Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove a real GOST-TLS handshake plus the gvpn AUTH + SESSION_BIND control protocol on the Android ABI, via one portable test run on the Linux `core` job and on the x86_64 emulator.

**Architecture:** A new test-only package `core/goste2e` runs, in one process, a loopback GOST-TLS connection (`gosttls.Listen` ⟵ `gosttls.Dial`, both via the engine) and drives `authgate` (AUTH gate) + `session` (SESSION_BIND) over it. The cert is minted CLI-free with `gosttls.GenerateSelfSignedGOSTCert`. The same binary runs on Linux (apt engine) and, cross-compiled for `android/amd64`, on the emulator (static engine).

**Tech Stack:** Go 1.24 + cgo, OpenSSL 3 + gost engine, Android NDK 26 / API 21, `reactivecircus/android-emulator-runner`, GitHub Actions.

**Execution model:** CI is the only Android verifier. Task 1 is fully verifiable on Linux (apt engine). Task 2 is CI-iterated (push → `gh run watch` → `gh run view --log-failed` → fix). Execute **inline**.

**Branch:** `feat/android-gost-e2e` (already created, spec already committed there).

---

## File Structure

- **Create** `core/goste2e/doc.go` — package clause + doc (so the package is a real, vet-clean package, not test-only-files). (Task 1)
- **Create** `core/goste2e/handshake_test.go` — the `TestGOSTControlHandshake` integration test. (Task 1)
- **Modify** `.github/workflows/build.yml` — extend the emulator job to also build/push/run the `goste2e` binary on the same emulator boot; rename the job. (Task 2)
- **Modify** `client/android/README.md` — note the on-device handshake+control check. (Task 3)

---

## Task 1: `core/goste2e` handshake + control test

**Files:**
- Create: `core/goste2e/doc.go`
- Create: `core/goste2e/handshake_test.go`

Verifiable locally on Linux with the apt gost engine.

- [ ] **Step 1: Create the package doc file**

Create `core/goste2e/doc.go`:

```go
// Package goste2e holds integration tests that exercise a real GOST-TLS
// handshake plus the gvpn AUTH + SESSION_BIND control protocol against the gost
// engine. It has no non-test API; it exists so `go test ./...` and the Android
// emulator job can compile and run the handshake e2e.
package goste2e
```

- [ ] **Step 2: Write the test**

Create `core/goste2e/handshake_test.go`:

```go
package goste2e

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/g00dvin/gvpn/core/authgate"
	"github.com/g00dvin/gvpn/core/gosttls"
	"github.com/g00dvin/gvpn/core/session"
)

// TestGOSTControlHandshake runs the gvpn client<->server control handshake over
// a real loopback GOST-TLS connection: a GOST-TLS handshake (both ends via the
// engine), then the AUTH gate and SESSION_BIND exchange. Cross-compiled for
// android/amd64 and run on the emulator, it proves the engine negotiates real
// GOST TLS and the framed control protocol works on the Android ABI.
//
// With GVPN_REQUIRE_GOST=1 a missing engine is fatal (not skipped) so CI / the
// emulator cannot false-green.
func TestGOSTControlHandshake(t *testing.T) {
	if err := gosttls.Init(); err != nil {
		if os.Getenv("GVPN_REQUIRE_GOST") == "1" {
			t.Fatalf("gost engine required but unavailable: %v", err)
		}
		t.Skipf("gost engine unavailable: %v", err)
	}

	// CLI-free GOST cert: the server presents it, the client pins it as CA.
	dir := t.TempDir()
	cert := filepath.Join(dir, "e2e.crt")
	key := filepath.Join(dir, "e2e.key")
	if err := gosttls.GenerateSelfSignedGOSTCert("e2e.gvpn", cert, key, 1); err != nil {
		t.Fatalf("GenerateSelfSignedGOSTCert: %v", err)
	}

	// Shared device identity for the AUTH gate.
	var deviceID [16]byte
	copy(deviceID[:], "gvpn-e2e-device!") // exactly 16 bytes
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatalf("rand psk: %v", err)
	}
	store := authgate.NewMapStore(map[[16]byte][]byte{deviceID: psk})
	gate := authgate.NewGate(store, nil) // nil decoy: the success path never invokes it
	mgr := session.NewManager(time.Minute)

	ln, err := gosttls.Listen("tcp", "127.0.0.1:0", gosttls.Config{CertFile: cert, KeyFile: key})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	type serverObs struct {
		res authgate.Result
		sid [16]byte
		err error
	}
	var obs serverObs
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			obs.err = err
			return
		}
		defer conn.Close()
		res, err := gate.Handle(conn)
		if err != nil {
			obs.err = err
			return
		}
		obs.res = res
		sess, err := mgr.Bind(res.DeviceID, conn)
		if err != nil {
			obs.err = err
			return
		}
		obs.sid = sess.SessionID
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cc, err := gosttls.Dial(ctx, "tcp", ln.Addr().String(),
		gosttls.Config{CAFile: cert, ServerName: "e2e.gvpn"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cc.Close()

	if err := authgate.WriteAuth(cc, psk, deviceID); err != nil {
		t.Fatalf("WriteAuth: %v", err)
	}
	var zeroSID [16]byte
	var zeroTok [32]byte
	newSID, _, err := session.ClientBind(cc, zeroSID, zeroTok)
	if err != nil {
		t.Fatalf("ClientBind: %v", err)
	}

	wg.Wait()
	if obs.err != nil {
		t.Fatalf("server: %v", obs.err)
	}

	// A real GOST suite was negotiated (not a fallback).
	if name := gosttls.CipherName(cc); !strings.Contains(name, "GOST") {
		t.Fatalf("negotiated cipher %q does not contain GOST", name)
	}
	// The AUTH gate verified the right device.
	if !obs.res.Authenticated || obs.res.Kind != authgate.KindDevice {
		t.Fatalf("gate result: authenticated=%v kind=%d", obs.res.Authenticated, obs.res.Kind)
	}
	if obs.res.DeviceID != deviceID {
		t.Fatalf("gate deviceID = %x, want %x", obs.res.DeviceID, deviceID)
	}
	// SESSION_BIND minted a non-zero session, agreed on both ends.
	if newSID == zeroSID {
		t.Fatalf("client session id is zero")
	}
	if obs.sid != newSID {
		t.Fatalf("session id mismatch: server %x client %x", obs.sid, newSID)
	}
}
```

- [ ] **Step 3: Verify it runs (not skipped) on Linux with the engine**

Run: `cd core && CGO_ENABLED=1 GVPN_REQUIRE_GOST=1 /home/goodvin/.local/go/bin/go test ./goste2e/ -run TestGOSTControlHandshake -v`
Expected: `--- PASS: TestGOSTControlHandshake` (RUN then PASS, not SKIP).

- [ ] **Step 4: Verify it cross-compiles for android/amd64**

This needs the NDK + cross-built OpenSSL/engine, which are CI-only; locally just confirm the package builds and vets for the host:

Run: `cd core && CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./goste2e/`
Expected: no vet errors.

- [ ] **Step 5: Commit**

```bash
git add core/goste2e/doc.go core/goste2e/handshake_test.go
git commit -m "goste2e: real GOST-TLS handshake + AUTH/SESSION_BIND control test"
```

---

## Task 2: CI — run the e2e on the emulator (same boot)

**Files:**
- Modify: `.github/workflows/build.yml`

Extend the existing `android-engine-smoke` job: after the self-test, build/push/run the `goste2e` binary on the same emulator boot. CI-iterated.

- [ ] **Step 1: Rename the job and add the e2e build step**

In `.github/workflows/build.yml`, rename the `android-engine-smoke` job's `name:` to `Android GOST on-device (engine + handshake)`. After the existing "Build self-test binary (android/amd64)" step, add a second build step:

```yaml
      - name: Build handshake e2e binary (android/amd64)
        if: steps.detect.outputs.present == 'true'
        working-directory: core
        env:
          ANDROID_NDK_HOME: ${{ env.ANDROID_HOME }}/ndk/${{ env.NDK_VERSION }}
          PKG_CONFIG_PATH: ${{ github.workspace }}/openssl-android/x86_64/lib/pkgconfig:${{ github.workspace }}/gost-engine-android/x86_64/lib/pkgconfig
        run: |
          CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android${ANDROID_API}-clang"
          CGO_ENABLED=1 GOOS=android GOARCH=amd64 CC="$CC" \
            go test -c -o "$GITHUB_WORKSPACE/goste2e.test" ./goste2e
```

- [ ] **Step 2: Run the e2e binary in the emulator step**

In the same job's "Run self-test on emulator" step, extend the `script:` to push and run the second binary after the self-test (one emulator boot):

```yaml
          script: |
            adb push "$GITHUB_WORKSPACE/gosttls.test" /data/local/tmp/gosttls.test
            adb shell chmod 755 /data/local/tmp/gosttls.test
            adb shell "cd /data/local/tmp && TMPDIR=/data/local/tmp GVPN_REQUIRE_GOST=1 ./gosttls.test -test.run TestEngineSelfTest -test.v" | tee /tmp/out.txt
            grep -q '^--- PASS: TestEngineSelfTest' /tmp/out.txt
            adb push "$GITHUB_WORKSPACE/goste2e.test" /data/local/tmp/goste2e.test
            adb shell chmod 755 /data/local/tmp/goste2e.test
            adb shell "cd /data/local/tmp && TMPDIR=/data/local/tmp GVPN_REQUIRE_GOST=1 ./goste2e.test -test.run TestGOSTControlHandshake -test.v" | tee /tmp/e2e.txt
            grep -q '^--- PASS: TestGOSTControlHandshake' /tmp/e2e.txt
```

- [ ] **Step 3: Push and iterate to green**

```bash
git add .github/workflows/build.yml
git commit -m "ci: run GOST handshake e2e on the emulator (same boot as engine smoke)"
git push -u origin feat/android-gost-e2e
```

Open the PR (triggers CI), then watch and fix:
```bash
gh pr create --title "Android GOST handshake + control e2e (on emulator)" --body "<summary>"
gh run list --branch feat/android-gost-e2e --limit 1
gh run watch <run-id> --exit-status
gh run view <run-id> --log-failed
```
Iterate until the job and all required checks are green. The `goste2e` cross-compile links the same OpenSSL+engine as the self-test, so the likely friction is test logic, not linking.

---

## Task 3: Docs + finalize

**Files:**
- Modify: `client/android/README.md`

- [ ] **Step 1: Note the on-device handshake check**

In `client/android/README.md`, under "What works today", add the handshake+control e2e to the emulator job's bullet: the job now also runs `core/goste2e` on the emulator, proving a real GOST-TLS handshake plus the gvpn AUTH gate + SESSION_BIND control protocol on-device (still short of a full WireGuard tunnel / device→host networking, which remain later sub-projects).

- [ ] **Step 2: Confirm CI still green and commit**

```bash
git add client/android/README.md
git commit -m "docs(android): note on-device GOST handshake + control e2e"
git push
```
Confirm the README push keeps the emulator job (and other required checks) green. The PR is mergeable once all checks are green.

---

## Self-Review

**Spec coverage:**
- Real GOST-TLS handshake on Android + AUTH + SESSION_BIND, loopback, CLI-free cert (spec Architecture/Components) → Task 1 test.
- Portable test on Linux `core` job + emulator (spec CI) → Task 1 Step 3 (Linux) + Task 2 (emulator); `go test ./...` picks up `core/goste2e` automatically.
- Env-gate `GVPN_REQUIRE_GOST=1`, never disable verification (spec Error handling) → Task 1 test (Init gate; client pins `CAFile`).
- Assertions: GOST cipher negotiated, gate device verified, session minted (spec Components) → Task 1 test assertions.
- Out of scope (WireGuard tunnel, device→host) → not present.
- Docs → Task 3.

**Placeholder scan:** the PR `--body "<summary>"` in Task 2 Step 3 is a CLI argument to fill at run time, not plan content; no `TODO`/"add error handling"/uncoded test steps.

**Type consistency:** `gosttls.{Init,GenerateSelfSignedGOSTCert,Listen,Dial,Config{CertFile,KeyFile,CAFile,ServerName},CipherName}`; `authgate.{NewMapStore,NewGate,WriteAuth,Result{Authenticated,Kind,DeviceID},KindDevice}`; `session.{NewManager,Manager.Bind,ClientBind,Session.SessionID}` — all match the signatures verified in `core` (`authgate`/`session` take `net.Conn`; no import cycle with `gosttls`). `GVPN_REQUIRE_GOST`, `TMPDIR=/data/local/tmp`, and the `PKG_CONFIG_PATH` engine dirs match Task 2's reuse of the SP3 emulator job.
