# Android GOST Engine Runtime (Milestone 3) — Design

**Status:** approved for planning (2026-06-24)
**Sub-project:** Client phase, SP3 — make `gosttls` actually work on Android.
**Predecessors:** SP1 `core/mobile` (PR #15), SP2 Android `.aar` cross-build (PR #16).

## Problem

SP2 produces `gvpn-core.aar`: a gomobile binding of `core/mobile` with `core/gosttls`
cross-compiled and **statically linked** against a cross-built OpenSSL 3.3.2
(`no-shared` → `libssl.a`/`libcrypto.a`). The `.aar` *builds*, but GOST TLS does
not yet *work* on a device.

The reason is engine loading. `gosttls.Init()`
(`core/gosttls/gosttls.go:18-27`) loads the GOST engine at runtime via:

```c
ENGINE *e = ENGINE_by_id("gost");
```

`ENGINE_by_id` is a **dynamic** lookup. On the Linux server it resolves a
system-installed `gost.so` through OpenSSL's `ENGINESDIR` (Debian package
`libengine-gost-openssl`). Android has **no ENGINESDIR and no `gost.so`**, so
`ENGINE_by_id("gost")` returns `NULL`, `Init()` errors, and no GOST handshake is
possible.

Milestone 3 makes the gost engine resolvable inside the statically-linked
OpenSSL on Android, and proves it on a real Android ABI via an emulator smoke
test in CI.

## Locked decisions

1. **Definition of done = on-device engine smoke.** CI cross-compiles + statically
   registers the engine, then an **x86_64 Android emulator** runs a focused test
   that asserts: `Init()` succeeds, `ENGINE_by_id("gost") != NULL`, and a GOST
   cert keygen → self-sign → verify round-trips in-process. **No full
   server↔device e2e handshake** (deferred).
2. **Integration = static engine, self-contained `.aar`.** Compile the
   gost-engine *sources* into a static library against the ABI's OpenSSL, link it
   into the cgo build, and register it **programmatically** so `ENGINE_by_id("gost")`
   resolves an in-binary engine — no `dlopen`, no ENGINESDIR, nothing extra
   shipped. SP2's static-OpenSSL model is preserved; the artifact stays one
   self-contained `.aar`.

## Architecture

**Platform split via Go build tags** is the spine. The only source change is
additive and Android-gated:

- **`//go:build !android` (Linux/server):** unchanged. `Init()` keeps doing the
  dynamic `ENGINE_by_id("gost")` against the apt-installed engine. The merged
  server (PR #1–#16) is byte-for-byte unaffected.
- **`//go:build android`:** a C shim statically registers the gost engine
  (`bind` → `ENGINE_add`) **before** the existing `ENGINE_by_id("gost")` call,
  which then succeeds against the in-binary engine. The rest of `Init()`
  (`ENGINE_init`, `ENGINE_set_default(ENGINE_METHOD_ALL)`) is shared.

```
Linux:   Init() ─────────────────────────► ENGINE_by_id("gost")  → gost.so via ENGINESDIR
Android: Init() ─► bind_gost(e) ─► ENGINE_add(e) ─► ENGINE_by_id("gost")  → in-binary engine
                   └────────── new, android-tagged C shim ──────────┘
```

No custom crypto, no disabled verification, no new VPN/TLS protocol — the engine
is upstream gost-engine, merely registered differently. Project hard constraints
hold.

## Components

### 1. `scripts/android/build-gost-engine-android.sh` (new)

Mirrors `build-openssl-android.sh`. Cross-compiles the gost engine to a **static**
archive against an ABI's cross-built OpenSSL.

- **Inputs (env):** `ANDROID_NDK_HOME` (required); `ABI` (`arm64-v8a` default |
  `x86_64`); `ANDROID_API` (default 21); `OPENSSL_PREFIX` (the SP2 OpenSSL
  install for this ABI, providing headers + `libcrypto.a`/`libssl.a`);
  `GOST_ENGINE_VERSION` (pinned tag/commit of `github.com/gost-engine/engine`);
  `PREFIX` (install dir for the engine archive + headers); `BUILD_DIR` (scratch).
- **Behavior:** put the NDK LLVM toolchain on `PATH` and export `ANDROID_NDK_ROOT`
  (same as SP2); fetch gost-engine at the pinned version; build it against
  `$OPENSSL_PREFIX` with the NDK toolchain (CMake with the NDK toolchain file, or
  direct clang if CMake fights the NDK), producing a static `libgost.a` (plus any
  internal static deps) and required headers under `$PREFIX`.
- **Reuses** SP2's ABI→OpenSSL-target mapping, NDK-on-PATH setup, and pinning
  discipline.

### 2. `core/gosttls` C shim + build tags (only source change)

- Split the engine loader currently in `gosttls.go`:
  - **`//go:build !android`** file: the existing `gvpn_load_gost_engine()`
    (dynamic `ENGINE_by_id`) verbatim.
  - **`//go:build android`** file: a variant that first registers the static
    engine (call the gost-engine bind entry point → `ENGINE_add`), then proceeds
    through the **same** `ENGINE_init` / `ENGINE_set_default` path and returns the
    `ENGINE*`.
- The Android cgo file carries the link/include flags for the static engine via
  `#cgo android CFLAGS/LDFLAGS`, env-steered like SP2 (CI exports the engine
  `PREFIX`; a developer overrides via the same vars). OpenSSL itself stays wired
  through `pkg-config` as today.
- **#1 unknown:** upstream `bind_gost` is `static` with `IMPLEMENT_DYNAMIC_BIND_FN`
  (intended for `dlopen`). Static registration needs a callable entry. The plan
  pins down the registration symbol and is prepared to add a tiny shim `.c`
  (compiled with the engine sources) exposing a `gvpn_bind_gost(ENGINE*, const
  char*)`. **CI is the only verifier** — expect push→watch→fix iteration.

### 3. Emulator self-test (reuse, no scaffolding)

A focused `gosttls` test — engine non-NULL + GOST keygen/self-sign/verify
round-trip, reusing `gencert.go`'s `GenerateSelfSignedGOSTCert` — compiled as an
`android/amd64` test binary via `go test -c` (NDK `CC`, OpenSSL via
`PKG_CONFIG_PATH`, engine via the same env flags), then `adb push` + `adb shell`
on an **x86_64** emulator. The test must avoid shelling out to the `openssl` CLI
(absent on the emulator) — it uses only the in-process engine.

**No Gradle/app skeleton.** Verifying the `.aar` through the Kotlin/JNI boundary
belongs to the future app-shell sub-project; here we exercise the exact cgo path
the `.aar` wraps.

## CI

Extend the Android `.aar` workflow to cover both ABIs:

1. **arm64-v8a (shipped artifact):** OpenSSL (cached, SP2) → gost engine static
   (new, cached) → `gomobile bind ./mobile` **with the engine linked** → upload
   `gvpn-core.aar`. The deliverable `.aar` now actually contains the engine.
2. **x86_64 (smoke test):** OpenSSL + gost engine static for x86_64 → `go test -c`
   the gosttls self-test for `android/amd64` → boot an x86_64 emulator via
   `reactivecircus/android-emulator-runner` → `adb push` the test binary →
   `adb shell` run → assert exit 0.

Self-test data flow on the emulator: `Init()` → static `bind` + `ENGINE_add` →
`ENGINE_by_id("gost")` non-NULL → `GenerateSelfSignedGOSTCert` (engine keygen
`gost2012_256` + self-sign `md_gost12_256`) → reload + verify.

## Error handling

- Android `Init()` returns a clear error if the engine is still `NULL` after the
  static bind — **no silent fallback, no disabling certificate verification**
  (the project's hard constraints are binding).
- Build tags guarantee the Linux server path is unchanged; a regression there
  would be a compile-time, not runtime, divergence.

## Testing

- **Linux CI (existing `core` job):** unchanged — `go vet` + `go test -race` with
  the apt engine proves the `!android` path still works.
- **Android x86_64 emulator (new):** the on-device smoke test above is the M3
  acceptance gate.
- **arm64 `.aar`:** building green with the engine linked proves the engine
  cross-compiles and links for the shipped ABI.

## Risk register

- **R1 (highest): static-linking gost-engine.** Upstream is CMake/dynamic-oriented;
  `bind_gost` is `static`. May need an upstream-shim `.c` or build-flag massaging.
  Pure CI iteration, no local verifier — expect several cycles, like SP2.
- **R2: emulator flakiness/time** in CI (boot + KVM). Mitigate with the well-used
  `android-emulator-runner` action, AVD caching, one x86_64 API level.
- **R3: NDK/CMake ↔ static-OpenSSL linking friction** (symbol/paramset mismatch).
  Same env-steering pattern as SP2.

## Out of scope (deferred)

- Full server↔device GOST handshake on the emulator (e2e).
- Gradle / `.aar`-through-JNI test; the Android app + `VpnService`.
- Other ABIs (`armeabi-v7a`, `x86`) and iOS.
- Mobile `Enroll` (needs gosttls certificate-fingerprint pinning).

## Execution model

CI is the only Android verifier (no local NDK/emulator). Execute **inline**
(push → `gh run watch` / `gh run view --log-failed` → fix → repeat), not
subagent-per-task, exactly as SP2.
