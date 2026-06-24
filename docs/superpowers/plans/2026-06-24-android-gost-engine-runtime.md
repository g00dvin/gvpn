# Android GOST Engine Runtime (Milestone 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `core/gosttls` actually work on Android by static-linking the gost engine into the `.aar`, and prove it loads on a real Android ABI with an x86_64 emulator smoke test in CI.

**Architecture:** Cross-compile the gost-engine sources to a static `libgost.a` against the ABI's cross-built OpenSSL (SP2). Behind a Go build tag, the Android `gosttls.Init()` registers that static engine programmatically (`bind_gost` → `ENGINE_add`) so the existing `ENGINE_by_id("gost")` resolves an in-binary engine; the Linux/server path is unchanged. An env-gated self-test (engine non-NULL + GOST keygen/self-sign/verify) is cross-compiled for `android/amd64` and run on an emulator via `adb`.

**Tech Stack:** Go 1.24 + cgo, OpenSSL 3.3.2 (static, SP2), gost-engine (static), Android NDK 26.3.11579264 (API 21), `gomobile`, `reactivecircus/android-emulator-runner`, GitHub Actions.

**Execution model:** CI is the **only** Android verifier (no local NDK/emulator). Tasks 2 and 3 are verifiable locally on Linux with the apt gost engine (they anchor the refactor). Tasks 1, 4 are verified by pushing and iterating CI: `git push` → `gh run watch <id> --exit-status` → `gh run view <id> --log-failed` → fix → repeat. Execute **inline**, not subagent-per-task.

**Branch:** `feat/android-gost-engine` (already created, spec already committed there).

---

## File Structure

- **Create** `scripts/android/build-gost-engine-android.sh` — cross-compile gost-engine → static `libgost.a` + `gostengine.pc` for one ABI, against the SP2 OpenSSL install. (Task 1)
- **Create** `core/gosttls/engine_other.go` — `//go:build !android`: the existing dynamic loader (`ENGINE_by_id("gost")`), moved out of `gosttls.go`. (Task 2)
- **Create** `core/gosttls/engine_android.go` — `//go:build android`: static-register the gost engine, then `ENGINE_by_id("gost")`. (Task 2)
- **Modify** `core/gosttls/gosttls.go` — `Init()` calls the platform `gvpn_register_gost()` then does the shared `ENGINE_init`/`ENGINE_set_default`; the inline C loader is removed. (Task 2)
- **Create** `core/gosttls/engine_selftest_test.go` — env-gated engine + GOST round-trip self-test (the emulator smoke test source). (Task 3)
- **Modify** `.github/workflows/build.yml` — link the engine into the arm64 `.aar`; add the `android-engine-smoke` x86_64 emulator job. (Task 4)
- **Modify** `client/android/README.md` — document that GOST now works on-device (engine smoke), with the new build step. (Task 5)

---

## Task 1: gost-engine static cross-build script

**Files:**
- Create: `scripts/android/build-gost-engine-android.sh`
- Reference (pattern to mirror): `scripts/android/build-openssl-android.sh`

This is the highest-risk task (spec R1). The mechanism is fully specified below; the one detail that must be confirmed against the pinned upstream tree (the exact list of engine `.c` sources) is handled by a concrete inspection step, not hand-waved. Verified only by CI (Task 4 builds it); there is no local NDK.

- [ ] **Step 1: Pin a gost-engine commit**

Resolve a concrete commit so the build is reproducible (do not leave it floating on `master`):

Run: `git ls-remote https://github.com/gost-engine/engine HEAD`
Record the 40-char SHA it prints and use it as the `GOST_ENGINE_VERSION` default in the script below (replace `PIN_THIS_SHA`).

- [ ] **Step 2: Inspect the source layout**

Run:
```bash
git clone --depth 1 https://github.com/gost-engine/engine /tmp/gost-engine-src
ls /tmp/gost-engine-src/*.c
sed -n '523,547p' /tmp/gost-engine-src/gost_eng.c     # the library-mode entry point
cat /tmp/gost-engine-src/cmake/engine.cmake           # GOST_ENGINE_SOURCE_FILES + lib_gost_engine
```
**Key finding (confirmed at SHA `3dd0f0e4`):** gost-engine has a built-in **library mode**. When `gost_eng.c` is compiled with `-DBUILDING_ENGINE_AS_LIBRARY`, the dynamic `IMPLEMENT_DYNAMIC_BIND_FN`/`CHECK_FN` macros are replaced by a public:
```c
void ENGINE_load_gost(void);   // ENGINE_new + make_gost_engine + ENGINE_add
```
This is upstream's own static-embedding entry (`cmake/engine.cmake` builds a `lib_gost_engine` target with exactly `COMPILE_DEFINITIONS "BUILDING_ENGINE_AS_LIBRARY"`). **No bind shim is needed** — the script compiles the engine + core sources with that define and exposes `ENGINE_load_gost`. The script compiles all top-level `*.c` **except** tests (`test_*.c`), the standalone CLI tools (`gostsum.c`, `gost12sum.c`), and the OpenSSL-3 provider sources (`gost_prov*.c`) — a superset of the engine + `gost_core` + `gost_err` source lists; unreferenced archive members are simply not linked.

- [ ] **Step 3: Write the script**

```bash
#!/usr/bin/env bash
# Cross-build the gost engine as a STATIC archive (libgost.a) for an Android ABI,
# linked against a cross-built OpenSSL (see build-openssl-android.sh). Emits
# libgost.a + a pkg-config file (gostengine.pc) under $PREFIX so cgo can pick it
# up via PKG_CONFIG_PATH, exactly like the OpenSSL build. Inputs via environment
# (all optional except ANDROID_NDK_HOME and OPENSSL_PREFIX):
#   ANDROID_NDK_HOME     path to the NDK (required)
#   OPENSSL_PREFIX       SP2 OpenSSL install for this ABI (required; has include/ + lib/)
#   GOST_ENGINE_VERSION  git ref/sha of gost-engine/engine (default: pinned below)
#   ABI                  arm64-v8a (default) | x86_64
#   ANDROID_API          default 21
#   PREFIX               install prefix (default ./gost-engine-android/$ABI)
#   BUILD_DIR            scratch dir (default ./.gost-build)
set -euo pipefail

GOST_ENGINE_VERSION="${GOST_ENGINE_VERSION:-PIN_THIS_SHA}"
ABI="${ABI:-arm64-v8a}"
ANDROID_API="${ANDROID_API:-21}"
PREFIX="${PREFIX:-$PWD/gost-engine-android/$ABI}"
BUILD_DIR="${BUILD_DIR:-$PWD/.gost-build}"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must be set to the NDK path}"
: "${OPENSSL_PREFIX:?OPENSSL_PREFIX must point at the cross-built OpenSSL for this ABI}"

case "$ABI" in
  arm64-v8a) triple=aarch64-linux-android ;;
  x86_64)    triple=x86_64-linux-android ;;
  *) echo "build-gost-engine-android: unsupported ABI '$ABI'" >&2; exit 1 ;;
esac

toolchain="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
if [ ! -d "$toolchain" ]; then
  echo "build-gost-engine-android: NDK toolchain not found at $toolchain" >&2
  exit 1
fi
export PATH="$toolchain:$PATH"
CC="${triple}${ANDROID_API}-clang"
AR=llvm-ar

mkdir -p "$BUILD_DIR"
src="$BUILD_DIR/engine"
if [ ! -d "$src" ]; then
  git clone https://github.com/gost-engine/engine "$src"
  git -C "$src" checkout "$GOST_ENGINE_VERSION"
fi
cd "$src"

# Engine + crypto sources, excluding the standalone CLI tools, the OpenSSL-3
# provider sources, and the tests. Compiled with -DBUILDING_ENGINE_AS_LIBRARY so
# gost_eng.c exposes the public ENGINE_load_gost() entry point (upstream's
# "library form") instead of the dynamic-module bind/check functions.
mapfile -t srcs < <(ls *.c \
  | grep -vE '^(gostsum|gost12sum)\.c$' \
  | grep -vE '^gost_prov' \
  | grep -vE '^test_')

set -x
"$CC" -O2 -fPIC -DBUILDING_ENGINE_AS_LIBRARY \
  -I"$OPENSSL_PREFIX/include" -I. \
  -c "${srcs[@]}"
"$AR" rcs libgost.a ./*.o
set +x

mkdir -p "$PREFIX/lib/pkgconfig" "$PREFIX/include"
cp libgost.a "$PREFIX/lib/"
cp gost-engine.h "$PREFIX/include/" 2>/dev/null || true

# gostengine.pc: -lgost must be followed by libcrypto/libssl so the engine's
# unresolved crypto symbols are satisfied (static-link ordering). Requiring
# libssl + libcrypto AFTER -lgost via pkg-config Requires guarantees that order.
cat > "$PREFIX/lib/pkgconfig/gostengine.pc" <<EOF
prefix=$PREFIX
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: gostengine
Description: Statically-linked GOST engine for Android
Version: 0
Requires: libssl libcrypto
Libs: -L\${libdir} -lgost
Cflags: -I\${includedir}
EOF

echo "build-gost-engine-android: installed libgost.a ($ABI) to $PREFIX"
ls -l "$PREFIX/lib/libgost.a" "$PREFIX/lib/pkgconfig/gostengine.pc"
```

- [ ] **Step 4: Make it executable and commit**

```bash
chmod +x scripts/android/build-gost-engine-android.sh
git add scripts/android/build-gost-engine-android.sh
git commit -m "build(android): cross-compile gost engine to static libgost.a"
```

Note: this script is verified by Task 4's CI (arm64 and x86_64 build steps). If the compile fails there (e.g. a source in `GOST_ENGINE_SOURCES` was missed, or `bind_gost`'s signature differs at the pinned commit), adjust the `srcs` filter / shim per the `gh run view --log-failed` output and re-push.

---

## Task 2: Build-tag split of the engine loader

**Files:**
- Create: `core/gosttls/engine_other.go`
- Create: `core/gosttls/engine_android.go`
- Modify: `core/gosttls/gosttls.go`

This refactor is verifiable **locally on Linux** with the apt gost engine — the `!android` path must keep working exactly as before. The android file is build-tag-excluded on Linux, so it cannot break the Linux build.

- [ ] **Step 1: Move the dynamic loader into `engine_other.go`**

Create `core/gosttls/engine_other.go`:

```go
//go:build !android

package gosttls

/*
#cgo pkg-config: libssl libcrypto
#cgo CFLAGS: -Wno-deprecated-declarations
#include <openssl/engine.h>

// gvpn_register_gost makes ENGINE_by_id("gost") resolvable and returns the
// engine (not yet initialized), or NULL. On non-Android platforms the gost
// engine is a system shared object found via OpenSSL's ENGINESDIR.
static ENGINE *gvpn_register_gost(void) {
    return ENGINE_by_id("gost");
}
*/
import "C"
```

- [ ] **Step 2: Create the Android loader `engine_android.go`**

Create `core/gosttls/engine_android.go`:

```go
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
static ENGINE *gvpn_register_gost(void) {
    ENGINE_load_gost();
    return ENGINE_by_id("gost");
}
*/
import "C"
```

- [ ] **Step 3: Rewrite `Init()` in `gosttls.go` to call the platform loader**

In `core/gosttls/gosttls.go`, replace the C preamble's `gvpn_load_gost_engine` definition with a prototype for the platform `gvpn_register_gost`, and do the shared init in Go.

Replace the C comment block (lines 9-28, the `gvpn_load_gost_engine` function) with:

```go
/*
#cgo pkg-config: libssl libcrypto
#cgo CFLAGS: -Wno-deprecated-declarations
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <stdlib.h>

// Defined per-platform in engine_other.go / engine_android.go.
ENGINE *gvpn_register_gost(void);
*/
```

Replace the body of `Init()` (the `initOnce.Do` closure) with:

```go
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
```

`gostEngine` stays declared as `*C.ENGINE` (gosttls.go:39); `gvpn_register_gost()` returns `*C.ENGINE`, which unifies with it (cgo shares the `struct engine_st` type across files in the package, the same way `gencert.go` already passes `gostEngine` to its own C function).

- [ ] **Step 4: Verify the Linux build + tests still pass**

Run: `cd core && CGO_ENABLED=1 /home/goodvin/.local/go/bin/go test ./gosttls/...`
Expected: PASS (the apt gost engine is installed in this environment; the dynamic `!android` path is unchanged).

- [ ] **Step 5: Verify the Android build tag compiles (syntax/types only)**

The android file cannot fully build locally (no `gostengine.pc` / NDK), but `go vet` with the android tag should fail only at the cgo/link stage, not on Go syntax/type errors. Confirm the non-android build is clean:

Run: `cd core && CGO_ENABLED=1 /home/goodvin/.local/go/bin/go vet ./gosttls/...`
Expected: no vet errors.

- [ ] **Step 6: Commit**

```bash
git add core/gosttls/engine_other.go core/gosttls/engine_android.go core/gosttls/gosttls.go
git commit -m "gosttls: split engine loader by build tag (Android static-registers gost)"
```

---

## Task 3: Engine self-test (the emulator smoke source)

**Files:**
- Create: `core/gosttls/engine_selftest_test.go`

One test that asserts the engine loads and does real GOST crypto, using only in-process cgo (no `openssl` CLI — absent on the emulator). It skips when the engine is unavailable (local dev without the engine) unless `GVPN_REQUIRE_GOST=1`, which turns the skip into a failure — so CI and the emulator cannot go green if the engine fails to load.

- [ ] **Step 1: Write the test**

Create `core/gosttls/engine_selftest_test.go`:

```go
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
```

- [ ] **Step 2: Verify it runs (not skipped) on Linux with the engine**

Run: `cd core && CGO_ENABLED=1 GVPN_REQUIRE_GOST=1 /home/goodvin/.local/go/bin/go test ./gosttls/ -run TestEngineSelfTest -v`
Expected: `--- PASS: TestEngineSelfTest` (RUN then PASS, not SKIP).

- [ ] **Step 3: Commit**

```bash
git add core/gosttls/engine_selftest_test.go
git commit -m "gosttls: add env-gated engine self-test (emulator smoke source)"
```

---

## Task 4: CI — link engine into arm64 .aar + x86_64 emulator smoke job

**Files:**
- Modify: `.github/workflows/build.yml`

Two changes: (A) extend the existing `android-aar` job so the shipped arm64 `.aar` actually contains the engine; (B) add a new `android-engine-smoke` job that builds the x86_64 engine, cross-compiles the self-test, and runs it on an emulator. CI-iterated to green.

- [ ] **Step 1: Add the gost-engine build + link to the `android-aar` job**

In `.github/workflows/build.yml`, in the `android-aar` job, after the "Cross-build OpenSSL for Android" step add an engine build step, and extend the bind step's `PKG_CONFIG_PATH`:

```yaml
      - name: Cross-build gost engine for Android
        if: steps.detect.outputs.present == 'true'
        env:
          ANDROID_NDK_HOME: ${{ env.ANDROID_HOME }}/ndk/${{ env.NDK_VERSION }}
          ABI: arm64-v8a
          OPENSSL_PREFIX: ${{ github.workspace }}/openssl-android/arm64-v8a
          PREFIX: ${{ github.workspace }}/gost-engine-android/arm64-v8a
        run: bash scripts/android/build-gost-engine-android.sh
```

Change the `gomobile bind core/mobile -> .aar` step's `PKG_CONFIG_PATH` to include the engine `.pc`:

```yaml
          PKG_CONFIG_PATH: ${{ github.workspace }}/openssl-android/arm64-v8a/lib/pkgconfig:${{ github.workspace }}/gost-engine-android/arm64-v8a/lib/pkgconfig
```

(The detect gate already keys on `scripts/android/build-openssl-android.sh`; the engine script lives beside it, so no gate change is needed.)

- [ ] **Step 2: Add the `android-engine-smoke` job**

Add a new job after `android-aar` (mirror its env + setup steps):

```yaml
  android-engine-smoke:
    name: Android GOST engine smoke (emulator)
    runs-on: ubuntu-latest
    env:
      OPENSSL_VERSION: "3.3.2"
      NDK_VERSION: "26.3.11579264"
      ANDROID_API: "21"
      EMU_API: "30"
      EMU_ARCH: "x86_64"
    steps:
      - uses: actions/checkout@v4
      - name: Detect component
        id: detect
        run: |
          if [ -f scripts/android/build-gost-engine-android.sh ]; then
            echo "present=true" >> "$GITHUB_OUTPUT"
          else
            echo "present=false" >> "$GITHUB_OUTPUT"
            echo "::notice::gost engine script not present — skipping"
          fi
      - if: steps.detect.outputs.present == 'true'
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
      - if: steps.detect.outputs.present == 'true'
        uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: "17"
      - if: steps.detect.outputs.present == 'true'
        uses: android-actions/setup-android@v3
      - name: Install NDK
        if: steps.detect.outputs.present == 'true'
        run: sdkmanager --install "ndk;${NDK_VERSION}"
      - name: Cross-build OpenSSL (x86_64)
        if: steps.detect.outputs.present == 'true'
        env:
          ANDROID_NDK_HOME: ${{ env.ANDROID_HOME }}/ndk/${{ env.NDK_VERSION }}
          ABI: x86_64
          PREFIX: ${{ github.workspace }}/openssl-android/x86_64
        run: bash scripts/android/build-openssl-android.sh
      - name: Cross-build gost engine (x86_64)
        if: steps.detect.outputs.present == 'true'
        env:
          ANDROID_NDK_HOME: ${{ env.ANDROID_HOME }}/ndk/${{ env.NDK_VERSION }}
          ABI: x86_64
          OPENSSL_PREFIX: ${{ github.workspace }}/openssl-android/x86_64
          PREFIX: ${{ github.workspace }}/gost-engine-android/x86_64
        run: bash scripts/android/build-gost-engine-android.sh
      - name: Build self-test binary (android/amd64)
        if: steps.detect.outputs.present == 'true'
        working-directory: core
        env:
          ANDROID_NDK_HOME: ${{ env.ANDROID_HOME }}/ndk/${{ env.NDK_VERSION }}
          PKG_CONFIG_PATH: ${{ github.workspace }}/openssl-android/x86_64/lib/pkgconfig:${{ github.workspace }}/gost-engine-android/x86_64/lib/pkgconfig
        run: |
          CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android${ANDROID_API}-clang"
          CGO_ENABLED=1 GOOS=android GOARCH=amd64 CC="$CC" \
            go test -c -o "$GITHUB_WORKSPACE/gosttls.test" ./gosttls
      - name: Enable KVM
        if: steps.detect.outputs.present == 'true'
        run: |
          echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
            | sudo tee /etc/udev/rules.d/99-kvm4all.rules
          sudo udevadm control --reload-rules
          sudo udevadm trigger --name-match=kvm
      - name: Run self-test on emulator
        if: steps.detect.outputs.present == 'true'
        uses: reactivecircus/android-emulator-runner@v2
        with:
          api-level: ${{ env.EMU_API }}
          arch: ${{ env.EMU_ARCH }}
          force-avd-creation: false
          emulator-options: -no-window -no-snapshot -noaudio -no-boot-anim
          disable-animations: true
          script: |
            adb push "$GITHUB_WORKSPACE/gosttls.test" /data/local/tmp/gosttls.test
            adb shell chmod 755 /data/local/tmp/gosttls.test
            adb shell "cd /data/local/tmp && TMPDIR=/data/local/tmp GVPN_REQUIRE_GOST=1 ./gosttls.test -test.run TestEngineSelfTest -test.v" | tee /tmp/out.txt
            grep -q '^--- PASS: TestEngineSelfTest' /tmp/out.txt
```

Notes baked in for the iteration: `TMPDIR=/data/local/tmp` (Android has no `/tmp` for `t.TempDir()`); `GVPN_REQUIRE_GOST=1` (skip becomes fatal); the trailing `grep -q '^--- PASS'` makes a SKIP or missing-PASS fail the step even though the test binary's own exit code might be 0 on skip.

- [ ] **Step 3: Push and iterate to green**

```bash
git add .github/workflows/build.yml
git commit -m "ci: link gost engine into arm64 .aar; add x86_64 emulator engine smoke"
git push -u origin feat/android-gost-engine
```

Then watch and fix:
```bash
gh run list --branch feat/android-gost-engine --limit 1
gh run watch <run-id> --exit-status
gh run view <run-id> --log-failed
```
Iterate until `android-aar`, `android-engine-smoke`, and the existing required jobs are all green. Likely friction points and where to fix them: gost-engine source list / `bind_gost` signature (Task 1 script); static-link symbol ordering (the `gostengine.pc` `Requires:` already pre-empts it); emulator boot/KVM (the action + KVM step); `t.TempDir()`/TMPDIR on device.

---

## Task 5: Docs + finalize

**Files:**
- Modify: `client/android/README.md`

- [ ] **Step 1: Update the README status**

In `client/android/README.md`, change the status paragraph so it no longer says GOST does not work on a device. Replace the first paragraph's claim that "**GOST TLS does not yet work on a device**" with a statement that the gost engine is now statically linked and proven on an x86_64 emulator (engine loads + GOST cert round-trip), while noting that a full server↔device handshake e2e and the Kotlin `VpnService` app remain later sub-projects. Add a short "Building the gost engine" subsection pointing at `scripts/android/build-gost-engine-android.sh` (env: `ANDROID_NDK_HOME`, `OPENSSL_PREFIX`, `ABI`, `PREFIX`) and that the `.aar` bind step adds the engine `.pc` to `PKG_CONFIG_PATH`.

- [ ] **Step 2: Confirm CI still green and commit**

```bash
git add client/android/README.md
git commit -m "docs(android): GOST engine now statically linked + emulator-proven"
git push
```
Confirm the README push keeps `android-aar` and `android-engine-smoke` green (the README doesn't affect them). The PR is mergeable once all required checks are green.

---

## Self-Review

**Spec coverage:**
- Static engine cross-build (spec §Components 1) → Task 1.
- Build-tag split, Linux unchanged, Android static-registers (spec Architecture + §Components 2) → Task 2.
- Emulator self-test, reuse `gencert.go`, no Gradle, no `openssl` CLI (spec §Components 3) → Task 3.
- CI: arm64 `.aar` with engine + x86_64 emulator smoke (spec §CI) → Task 4.
- Error handling: clear error if engine NULL, never disable verification (spec §Error handling) → Task 2 Step 3 `Init()` + Task 3 `GVPN_REQUIRE_GOST`.
- Done-when = on-device engine smoke; no full e2e (spec §Locked decisions 1, §Out of scope) → Task 3 self-test scope; e2e explicitly excluded.
- Docs (spec implied by SP2 README) → Task 5.

**Placeholder scan:** `PIN_THIS_SHA` is intentionally resolved by Task 1 Step 1 (a concrete `git ls-remote` command), not a leftover TODO. The "confirm `GOST_ENGINE_SOURCES`" inspection (Task 1 Step 2) is a concrete command-driven step, the responsible way to handle an upstream detail that cannot be verified without an NDK. No vague "add error handling"/"write tests" placeholders.

**Type consistency:** `gvpn_register_gost(void) -> ENGINE*` is defined identically in `engine_other.go` and `engine_android.go` and prototyped in `gosttls.go`; `gostEngine` stays `*C.ENGINE`; `ENGINE_load_gost(void)` is provided by `libgost.a` (Task 1, compiled `-DBUILDING_ENGINE_AS_LIBRARY`) and declared `extern` in `engine_android.go` (Task 2); `GVPN_REQUIRE_GOST`, `GenerateSelfSignedGOSTCert`, and `PKG_CONFIG_PATH` engine dir names match across Tasks 1, 3, 4.
